# coding=utf-8
# Multi-Model topology
"""
Copyright 2019-present Open Networking Foundation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import argparse
import os
import stratum
from stratum import StratumBmv2Switch
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import Host
from mininet.topo import Topo
from mininet.node import Controller, RemoteController
from mininet.link import Intf

import subprocess

CPU_PORT = 255

class TutorialTopo(Topo):
    """2x2 fabric topology with IPv6 hosts"""

    def __init__(self):
        Topo.__init__(self)
        self.addSwitch("satellite1", cls=StratumBmv2Switch, cpuport=CPU_PORT)
        self.addSwitch("satellite1", cls=StratumBmv2Switch, cpuport=CPU_PORT)
        self.addSwitch("satellite1", cls=StratumBmv2Switch, cpuport=CPU_PORT)


switches = {'stratum-bmv2': StratumBmv2Switch}

TOPOS = {'tutorialtopo':TutorialTopo}

topos = {'custom': (lambda: TutorialTopo())}


def main():
    net = Mininet(topo=TutorialTopo(), controller=None)
    net.start()

    CLI(net)
    net.stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Mininet topology script for 2x2 fabric with stratum_bmv2 and IPv6 hosts')
    args = parser.parse_args()
    setLogLevel('info')

    main()


