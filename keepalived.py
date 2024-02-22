#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-

# Copyright 2023 Red Hat Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import collections
import datetime
import gzip
import os.path
from pathlib import Path
import sys
import time
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QPalette, QColor, QPixmap, QPainter
from PyQt6.QtWidgets import QWidget, QApplication, QLineEdit, QHBoxLayout, QVBoxLayout, QPushButton, QFileDialog, QLabel, QFrame, QScrollArea, QErrorMessage, QProgressBar

platforms = ['kni', 'nutanix', 'openstack', 'ovirt', 'vsphere']
namespaces = []
for platform in platforms:
   namespaces.append(f'openshift-{platform}-infra')

scriptSucceeded = 'Script succeeded'
scriptFailed = 'Script failed'
tookVip = 'Took VIP'
lostVip = 'Lost VIP'
reloading = 'Reloading'
nodeAddress = 'Node address'
class LogEntry(object):
   def __init__(self, timestamp: datetime.datetime=None, line: str=None, event: str=None):
      self.timestamp = timestamp
      self.line = line
      self.event = event
      # 0 = API 0, 1 = API 1, 2 = Ingress 0, 3 = Ingress 1
      self.vip = 0

   def __str__(self):
      return f'{self.vip} {self.event} - {self.timestamp}: {self.line}'

   def __repr__(self):
      return f'{self.vip} {self.event} - {self.timestamp}: {self.line}'


class NodeData(object):
   def __init__(self):
      self.vipChanges = [[], [], [], []]
      self.events = []
      self.addrs = set()

   def __repr__(self):
      return f'{self.vipChanges} {self.events} {self.addrs}'


class KeepalivedLogParser(QWidget):
   def __init__(self, parent = None):
      QWidget.__init__(self, parent)
      self.setAcceptDrops(True)
      self.logFiles = []
      self.logEntries = collections.OrderedDict()
      self.nodeData = collections.OrderedDict()
      # Earliest and latest timestamps in the logs
      self.timeBounds = [None, None]
      self.vips = ['', '', '', '']
      
      self.layout = QVBoxLayout(self)

      self.pathLayout = QHBoxLayout()
      self.selectPathButton = QPushButton('Select Path')
      self.selectPathButton.clicked.connect(self.selectPath)
      self.pathLayout.addWidget(self.selectPathButton)
      self.pathBox = QLineEdit()
      self.pathLayout.addWidget(self.pathBox)

      self.viewScroll = QScrollArea()
      self.viewScroll.setWidgetResizable(True)
      self.viewLayout = QVBoxLayout(self.viewScroll)
      frame = QFrame(self.viewScroll)
      frame.setLayout(self.viewLayout)
      self.viewScroll.setWidget(frame)

      self.globalLayout = QHBoxLayout()
      self.timespanLabel = QLabel()
      self.globalLayout.addWidget(self.timespanLabel)
      self.vipLabel = QLabel()
      self.globalLayout.addWidget(self.vipLabel)

      self.progressBar = QProgressBar()
      self.progressBar.setRange(0, 4)
      self.progressText = QLabel()

      self.layout.addLayout(self.pathLayout, 1)
      self.layout.addWidget(self.viewScroll, 100)
      self.layout.addLayout(self.globalLayout, 1)
      self.layout.addWidget(self.progressBar, 1)
      self.layout.addWidget(self.progressText, 1)
      
      self.resize(1024, 768)
      self.setWindowTitle('Keepalived Log Parser')
      self.show()

   def setProgress(self, val, text):
      self.progressText.setText(text)
      self.progressBar.setValue(val)

   def selectPath(self):
      startDir = os.path.expanduser('~')
      self.basePath = QFileDialog.getExistingDirectory(self, directory=startDir)
      self.run()

   def run(self):
      self.pathBox.setText(self.basePath)
      try:
         self.findLogs()
         self.parseLogs()
         self.progressText.setText('Processing log entries')
         self.processEntries()
         self.progressText.setText('Populating UI')
         self.populateView()
         self.setProgress(len(self.logFiles), 'Done')
         self.progressText.setText('Done')
      except Exception as e:
         messageDialog = QErrorMessage(self)
         messageDialog.showMessage(f'Error: {e}')
         raise

   def findLogs(self):
      p = Path(self.basePath)
      topLevelDirs = [i for i in p.iterdir() if i.is_dir()]
      self.isMustGather = False
      for d in topLevelDirs:
         if d.name == 'namespaces':
            self.isMustGather = True
            namespaceDir = d
      if self.isMustGather:
         for namespace in namespaces:
            checkPath = namespaceDir.joinpath(namespace, 'pods')
            if checkPath.exists():
               for pod in checkPath.iterdir():
                  if 'keepalived' in pod.name:
                     podLogs = pod.joinpath('keepalived', 'keepalived', 'logs')
                     rotatedPath = podLogs.joinpath('rotated')
                     if rotatedPath.exists():
                        for r in rotatedPath.iterdir():
                           self.logFiles.append(r)
                     self.logFiles.append(podLogs.joinpath('current.log'))
                     self.logFiles.append(podLogs.joinpath('current.insecure.log'))
      else:
         self.logFiles = [i for i in p.iterdir() if i.is_file()]

      self.logFiles = sorted(self.logFiles)

   def parseLogs(self):
      self.progressBar.setRange(0, len(self.logFiles))
      count = 0
      for f in self.logFiles:
         # The filenames get unreadably long in must-gathers, so shorten them
         # while trying to keep the interesting bits
         shortname = str(f)
         if len(shortname) > 125:
            shortname = shortname[:25] + '...' + shortname[-100:]
         self.setProgress(count, f'Parsing file {shortname}')
         count += 1

         name = f.name
         if self.isMustGather:
            # This is the pod name since all of the filenames are the same
            name = f.parts[f.parts.index('pods') + 1]
         self.logEntries.setdefault(name, [])
         gratuitousArp = [False, False, False, False]
         smartopen = open
         if f.parts[-1].endswith('.gz'):
            smartopen = gzip.open
         with smartopen(f, 'rt') as handle:
            for line in handle:
               timestamp = self.getTime(line)
               # Update start and end times if necessary
               if self.timeBounds[0] is None or timestamp < self.timeBounds[0]:
                  self.timeBounds[0] = timestamp
               if self.timeBounds[1] is None or timestamp > self.timeBounds[1]:
                  self.timeBounds[1] = timestamp
               # Look for log messages we care about
               if 'VRRP_Script' in line and ('succeeded' in line or 'failed' in line):
                  entry = LogEntry(timestamp, line, scriptFailed)
                  if 'succeeded' in line:
                     entry.event = scriptSucceeded
                  entry.vip = 1
                  if 'chk_ocp' in line:
                     entry.vip = 0
                  self.logEntries[name].append(entry)
               # Check for gratuitous ARP messages to find out where the VIP is if the logs start
               # after the VIP was assigned
               if 'Sending/queueing gratuitous ARPs' in line or 'Sending/queueing Unsolicited Neighbour Adverts' in line:
                  entry = LogEntry(timestamp, line, tookVip)
                  self.setEntryVip(entry, line)
                  self.vips[entry.vip] = line.split()[-1]
                  if not gratuitousArp[entry.vip]:
                     # Only do this once per VIP since after that we should get normal events
                     gratuitousArp[entry.vip] = True
                     self.logEntries[name].append(entry)
               if 'Entering MASTER STATE' in line:
                  entry = LogEntry(timestamp, line, tookVip)
                  self.setEntryVip(entry, line)
                  # If we already found the VIP we don't need to do this
                  gratuitousArp[entry.vip] = True
                  self.logEntries[name].append(entry)
               if 'Entering BACKUP STATE' in line:
                  entry = LogEntry(timestamp, line, lostVip)
                  self.setEntryVip(entry, line)
                  self.logEntries[name].append(entry)
               if 'Reloading ...' in line:
                  entry = LogEntry(timestamp, line, reloading)
                  self.logEntries[name].append(entry)
               if 'Assigned address' in line:
                  entry = LogEntry(timestamp, line, nodeAddress)
                  self.logEntries[name].append(entry)

   def setEntryVip(self, entry, line):
      # LogEntry defaults to vip 0
      if 'API_1' in line:
         entry.vip = 1
      # Pre-dual stack VIPs there was no number
      elif 'INGRESS_0' in line or '_INGRESS)' in line:
         entry.vip = 2
      elif 'INGRESS_1' in line:
         entry.vip = 3

   def processEntries(self):
      if len(self.logEntries.items()) == 0:
         raise Exception('No log entries')
      for name, entries in self.logEntries.items():
         self.nodeData[name] = NodeData()
         haveVip = [False, False, False, False]
         # Sort the entries because they may have come from multiple files, which are not
         # necessarily in chronological order.
         for entry in sorted(entries, key=lambda x: x.timestamp):
            # VIP events
            if haveVip[entry.vip]:
               if entry.event == lostVip:
                  self.nodeData[name].vipChanges[entry.vip].append(entry.timestamp)
                  haveVip[entry.vip] = False
            elif entry.event == tookVip:
               self.nodeData[name].vipChanges[entry.vip].append(entry.timestamp)
               haveVip[entry.vip] = True
            # Healthcheck events
            if entry.event in [scriptSucceeded, scriptFailed]:
               self.nodeData[name].events.append(entry)
            if entry.event == reloading:
               self.nodeData[name].events.append(entry)
            if entry.event == nodeAddress:
               parts = entry.line.split()
               currentAddr = parts[parts.index('address') + 1]
               self.nodeData[name].addrs.add(currentAddr)

   def populateView(self):
      # Global values
      duration = str(self.timeBounds[1] - self.timeBounds[0])
      timespan = f'Start: {self.timeBounds[0]}   End: {self.timeBounds[1]}   Duration: {duration}'
      self.timespanLabel.setText(timespan)
      self.vipLabel.setText(f'VIPs: {self.vips[0]} {self.vips[1]} {self.vips[2]} {self.vips[3]}')
      # Node-specific values
      for node, data in self.nodeData.items():
         nodeLayout = QHBoxLayout()
         nodeInfoLayout = QVBoxLayout()
         nameEdit = QLineEdit(node)
         nameEdit.setMinimumWidth(200)
         nodeInfoLayout.addWidget(nameEdit, 1)
         for addr in data.addrs:
            addrLabel = QLabel(addr)
            nodeInfoLayout.addWidget(addrLabel, 1)
         nodeInfoLayout.addStretch(100)
         nodeLayout.addLayout(nodeInfoLayout)
         timelineLayout = QVBoxLayout()
         nodeLayout.addLayout(timelineLayout, 100)

         self.viewLayout.addLayout(nodeLayout)

         def addLabel(start: datetime.datetime, change: datetime.datetime, haveVip: bool):
            length = (change - start).total_seconds()
            changeLabel = QLabel()
            changeLabel.setToolTip(str(start) + ' - ' + str(change))
            changeLabel.setFrameStyle(QFrame.Shape.Box)
            changeLabel.setStyleSheet('color: red; border: 1px solid red; border-style: dashed')
            if haveVip:
               changeLabel.setStyleSheet('color: lime;')
            vipLayout.addWidget(changeLabel, int(length))

         for vip in range(4):
            start = self.timeBounds[0]
            vipLayout = QHBoxLayout()
            vipLayout.setSpacing(0)
            haveVip = False
            for change in data.vipChanges[vip]:
               addLabel(start, change, haveVip)
               start = change
               haveVip = not haveVip
            addLabel(start, self.timeBounds[1], haveVip)
            timelineLayout.addLayout(vipLayout)

         def addEventLabel(start: datetime.datetime, entry: LogEntry):
            length = max((entry.timestamp - start).total_seconds(), 1)
            checkLabel = QLabel()
            checkLabel.setToolTip(entry.line)
            checkLabel.setFrameStyle(QFrame.Shape.Box)
            checkLabel.setStyleSheet('color: red')
            if entry.event == scriptSucceeded:
               checkLabel.setStyleSheet('color: lime')
            elif entry.event == reloading:
               checkLabel.setStyleSheet('color: blue')
            vipLayout.addStretch(int(length) - 1)
            vipLayout.addWidget(checkLabel, 1)

         start = self.timeBounds[0]
         vipLayout = QHBoxLayout()
         vipLayout.setSpacing(0)
         for entry in data.events:
            addEventLabel(start, entry)
            start = entry.timestamp
         remaining = (self.timeBounds[1] - start).total_seconds()
         vipLayout.addStretch(int(remaining))
         timelineLayout.addLayout(vipLayout)

   def getTime(self, line: str) -> time.struct_time:
      return datetime.datetime.fromisoformat(line.split()[0]).replace(microsecond=0)

   def dragEnterEvent(self, event):
      if event.mimeData().hasFormat('text/plain'):
         event.acceptProposedAction()

   def dropEvent(self, event):
      path = Path(*Path(event.mimeData().text()).parts[1:])
      self.basePath = '/' + str(path)
      print(self.basePath)
      event.acceptProposedAction()
      self.run()

if __name__ == '__main__':
   app = QApplication(sys.argv)
   
   form = KeepalivedLogParser()
   
   sys.exit(app.exec())
