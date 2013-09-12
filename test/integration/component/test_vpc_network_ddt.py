# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

""" Component tests for VPC network functionality
"""
#Import Local Modules
import marvin
from nose.plugins.attrib import attr
from marvin.cloudstackTestCase import *
from marvin.cloudstackAPI import *
from marvin.integration.lib.utils import *
from marvin.integration.lib.base import *
from marvin.integration.lib.common import *
from marvin.remoteSSHClient import remoteSSHClient
import datetime
from ddt import ddt, data

class Services:
    """Test VPC network services
    """

    def __init__(self):
        self.services = {
            "account": {
                "email": "test@test.com",
                "firstname": "Test",
                "lastname": "User",
                "username": "test",
                # Random characters are appended for unique
                # username
                "password": "password",
            },
            "service_offering": {
                "name": "Tiny Instance",
                "displaytext": "Tiny Instance",
                "cpunumber": 1,
                "cpuspeed": 100,
                "memory": 128,
            },
            "network_offering": {
                "name": 'VPC Network offering',
                "displaytext": 'VPC Network off',
                "guestiptype": 'Isolated',
                "supportedservices": 'Vpn,Dhcp,Dns,SourceNat,PortForwarding,Lb,UserData,StaticNat,NetworkACL',
                "traffictype": 'GUEST',
                "availability": 'Optional',
                "useVpc": 'on',
                "serviceProviderList": {
                    "Vpn": 'VpcVirtualRouter',
                    "Dhcp": 'VpcVirtualRouter',
                    "Dns": 'VpcVirtualRouter',
                    "SourceNat": 'VpcVirtualRouter',
                    "PortForwarding": 'VpcVirtualRouter',
                    "Lb": 'VpcVirtualRouter',
                    "UserData": 'VpcVirtualRouter',
                    "StaticNat": 'VpcVirtualRouter',
                    "NetworkACL": 'VpcVirtualRouter'
                },
                "serviceCapabilityList": {
                    "SourceNat": {"SupportedSourceNatTypes": "peraccount"},
                },
            },
            "network_off_netscaler": {
                "name": 'Network offering-netscaler',
                "displaytext": 'Network offering-netscaler',
                "guestiptype": 'Isolated',
                "supportedservices": 'Dhcp,Dns,SourceNat,PortForwarding,Vpn,Lb,UserData,StaticNat',
                "traffictype": 'GUEST',
                "availability": 'Optional',
                "useVpc": 'on',
                "serviceProviderList": {
                    "Dhcp": 'VpcVirtualRouter',
                    "Dns": 'VpcVirtualRouter',
                    "SourceNat": 'VpcVirtualRouter',
                    "PortForwarding": 'VpcVirtualRouter',
                    "Vpn": 'VpcVirtualRouter',
                    "Lb": 'Netscaler',
                    "UserData": 'VpcVirtualRouter',
                    "StaticNat": 'VpcVirtualRouter',
                },
                "serviceCapabilityList": {
                    "SourceNat": {"SupportedSourceNatTypes": "peraccount"},
                },
            },
            "network_offering_vpcNS": {
                                    "name": 'VPC Network offering',
                                    "displaytext": 'VPC Network off',
                                    "guestiptype": 'Isolated',
                                    "supportedservices": 'Vpn,Dhcp,Dns,SourceNat,PortForwarding,Lb,UserData,StaticNat,NetworkACL',
                                    "traffictype": 'GUEST',
                                    "availability": 'Optional',
                                    "useVpc": 'on',
                                    "serviceProviderList": {
                                            "Vpn": 'VpcVirtualRouter',
                                            "Dhcp": 'VpcVirtualRouter',
                                            "Dns": 'VpcVirtualRouter',
                                            "SourceNat": 'VpcVirtualRouter',
                                            "PortForwarding": 'VpcVirtualRouter',
                                            "Lb": 'Netscaler',
                                            "UserData": 'VpcVirtualRouter',
                                            "StaticNat": 'VpcVirtualRouter',
                                            "NetworkACL": 'VpcVirtualRouter'
                                        },
                                   "serviceCapabilityList": {
                                        "SourceNat": {
                                            "SupportedSourceNatTypes": "peraccount"
                                        },
                                        "lb": {
                                               "SupportedLbIsolation": "dedicated"
                                        },
                                    },
                                },

            "network_off_shared": {
                "name": 'Shared Network offering',
                "displaytext": 'Shared Network offering',
                "guestiptype": 'Shared',
                "traffictype": 'GUEST',
                "availability": 'Optional',
                "useVpc": 'on',
                "specifyIpRanges": True,
                "specifyVlan": True
            },
            "vpc_offering": {
                "name": 'VPC off',
                "displaytext": 'VPC off',
                "supportedservices": 'Dhcp,Dns,SourceNat,PortForwarding,Vpn,Lb,UserData,StaticNat',
            },
            "vpc": {
                "name": "TestVPC",
                "displaytext": "TestVPC",
                "cidr": '10.0.0.1/24'
            },
            "netscaler": {
                        "ipaddress": '10.102.192.50',
                        "username": 'nsroot',
                        "password": 'nsroot',
                        "networkdevicetype": 'NetscalerVPXLoadBalancer',
                        "publicinterface": '1/3',
                        "privateinterface": '1/4',
                        "numretries": 2,
                        "lbdevicededicated": True,
                        "lbdevicecapacity": 50,
                        "port": 22,
            },
            "network": {
                "name": "Test Network",
                "displaytext": "Test Network",
                "netmask": '255.255.255.0'
            },
            "lbrule": {
                "name": "SSH",
                "alg": "leastconn",
                # Algorithm used for load balancing
                "privateport": 22,
                "publicport": 2222,
                "openfirewall": False,
                "startport": 22,
                "endport": 2222,
                "protocol": "TCP",
                "cidrlist": '0.0.0.0/0',
            },
            "natrule": {
                "privateport": 22,
                "publicport": 22,
                "startport": 22,
                "endport": 22,
                "protocol": "TCP",
                "cidrlist": '0.0.0.0/0',
            },
            "fw_rule": {
                "startport": 1,
                "endport": 6000,
                "cidr": '0.0.0.0/0',
                # Any network (For creating FW rule)
                "protocol": "TCP"
            },
            "icmp_rule": {
                "icmptype": -1,
                "icmpcode": -1,
                "cidrlist": '0.0.0.0/0',
                "protocol": "ICMP"
            },
            "virtual_machine": {
                "displayname": "Test VM",
                "username": "root",
                "password": "password",
                "ssh_port": 22,
                "hypervisor": 'XenServer',
                # Hypervisor type should be same as
                # hypervisor type of cluster
                "privateport": 22,
                "publicport": 22,
                "protocol": 'TCP',
            },
            "ostype": 'CentOS 5.3 (64-bit)',
            # Cent OS 5.3 (64 bit)
            "sleep": 60,
            "timeout": 10,
        }

@ddt
class TestVPCNetwork(cloudstackTestCase):

    @classmethod
    def setUpClass(cls):
        cls.api_client = super(
                               TestVPCNetwork,
                               cls
                               ).getClsTestClient().getApiClient()
        cls.services = Services().services
        # Get Zone, Domain and templates
        cls.domain = get_domain(cls.api_client, cls.services)
        cls.zone = get_zone(cls.api_client, cls.services)
        cls.template = get_template(
                            cls.api_client,
                            cls.zone.id,
                            cls.services["ostype"]
                            )
        cls.services["virtual_machine"]["zoneid"] = cls.zone.id
        cls.services["virtual_machine"]["template"] = cls.template.id

        cls._cleanup = []
        cls.service_offering = ServiceOffering.create(
                                            cls.api_client,
                                            cls.services["service_offering"]
                                            )
        cls._cleanup.append(cls.service_offering)
        # Configure Netscaler device
        global NSconfigured
        
        try:
           cls.netscaler = add_netscaler(cls.api_client, cls.zone.id, cls.services["netscaler"])
           cls._cleanup = [
                    cls.netscaler
                    ]
           NSconfigured = True
        except Exception as e:
           NSconfigured = False
           raise Exception ("Warning: Exception in setUpClass: %s" % e)

        return

    @classmethod
    def tearDownClass(cls):
        try:
            #Cleanup resources used
            cleanup_resources(cls.api_client, cls._cleanup)
        except Exception as e:
            raise Exception("Warning: Exception during cleanup : %s" % e)
        return

    def setUp(self):
        self.services = Services().services
        self.apiclient = self.testClient.getApiClient()
        self.dbclient = self.testClient.getDbConnection()
        self.account = Account.create(
                                     self.apiclient,
                                     self.services["account"],
                                     admin=True,
                                     domainid=self.domain.id
                                     )
        self.cleanup = []
        self.cleanup.insert(0, self.account)
        return

    def tearDown(self):
        try:
            cleanup_resources(self.apiclient, self.cleanup)
        except Exception as e:
            self.debug("Warning: Exception during cleanup : %s" % e)
            #raise Exception("Warning: Exception during cleanup : %s" % e)
        return

    #def validate_vpc_offering(self, vpc_offering):
    #    """Validates the VPC offering"""

        #self.debug("Check if the VPC offering is created successfully?")
        #vpc_offs = VpcOffering.list(
        #                            self.apiclient,
        #                            id=vpc_offering.id
        #                            )
        #self.assertEqual(
        #                 isinstance(vpc_offs, list),
        #                 True,
        #                 "List VPC offerings should return a valid list"
        #                 )
        #self.assertEqual(
        #         vpc_offering.name,
        #         vpc_offs[0].name,
        #        "Name of the VPC offering should match with listVPCOff data"
        #        )
        #self.debug(
        #        "VPC offering is created successfully - %s" %
        #                                                vpc_offering.name)
        #return

    def validate_vpc_network(self, network, state=None):
        """Validates the VPC network"""

        self.debug("Check if the VPC network is created successfully?")
        vpc_networks = VPC.list(
                                    self.apiclient,
                                    id=network.id
                          )
        self.assertEqual(
                         isinstance(vpc_networks, list),
                         True,
                         "List VPC network should return a valid list"
                         )
        self.assertEqual(
                 network.name,
                 vpc_networks[0].name,
                "Name of the VPC network should match with listVPC data"
                )
        if state:
            self.assertEqual(
                 vpc_networks[0].state,
                 state,
                "VPC state should be '%s'" % state
                )
        self.debug("VPC network validated - %s" % network.name)
        return
    
    @data("network_offering", "network_offering_vpcNS")
    @attr(tags=["advanced", "intervlan"])
    def test_01_create_network(self, value):
        """ Test create network in VPC
        """

        # Validate the following
        # 1. Create VPC Offering by specifying all supported Services
        #    (Vpn,dhcpdns,UserData, SourceNat,Static NAT and PF,LB,NetworkAcl)
        # 2. Create a VPC using the above VPC offering.
        # 3. Create a network offering with guest type=Isolated" that has
        #    all of supported Services(Vpn,dhcpdns,UserData, SourceNat,Static
        #    NAT,LB and PF,LB,NetworkAcl ) provided by VPCVR and conserver
        #    mode is ON
        # 4. Create a VPC using the above VPC offering.
        # 5. Create a network using the network offering created in step2 as
        #    part of this VPC.


        if (value == "network_offering_vpcNS" and NSconfigured == False):
           self.skipTest('Netscaler not configured: skipping test')

        if (value == "network_offering"):
           vpc_off_list=VpcOffering.list(
                                  self.apiclient,
                                  name='Default VPC offering',
                                  listall=True
                                  )
        else:
           vpc_off_list=VpcOffering.list(
                                  self.apiclient,
                                  name='Default VPC  offering with Netscaler',
                                  listall=True
                                  )
        if isinstance(vpc_off_list, list):
           vpc_off=vpc_off_list[0]
        self.debug("Creating a VPC with offering: %s" % vpc_off.id)

        self.services["vpc"]["cidr"] = '10.1.1.1/16'
        vpc = VPC.create(
                         self.apiclient,
                         self.services["vpc"],
                         vpcofferingid=vpc_off.id,
                         zoneid=self.zone.id,
                         account=self.account.name,
                         domainid=self.account.domainid
                         )
        self.validate_vpc_network(vpc)

        self.network_offering = NetworkOffering.create(
                                            self.apiclient,
                                            self.services[value],
                                            conservemode=False
                                            )
        # Enable Network offering
        self.network_offering.update(self.apiclient, state='Enabled')
        self.cleanup.append(self.network_offering)

        # Creating network using the network offering created
        self.debug("Creating network with network offering: %s" %
                                                    self.network_offering.id)
        network = Network.create(
                                self.apiclient,
                                self.services["network"],
                                accountid=self.account.name,
                                domainid=self.account.domainid,
                                networkofferingid=self.network_offering.id,
                                zoneid=self.zone.id,
                                gateway='10.1.1.1',
                                vpcid=vpc.id
                                )
        self.debug("Created network with ID: %s" % network.id)
        self.debug(
            "Verifying list network response to check if network created?")
        networks = Network.list(
                                self.apiclient,
                                id=network.id,
                                listall=True
                                )
        self.assertEqual(
                         isinstance(networks, list),
                         True,
                         "List networks should return a valid response"
                         )
        nw = networks[0]

        self.assertEqual(
            nw.networkofferingid,
            self.network_offering.id,
            "Network should be created from network offering - %s" %
                                                    self.network_offering.id
             )
        self.assertEqual(
                         nw.vpcid,
                         vpc.id,
                         "Network should be created in VPC: %s" % vpc.name
                         )
        return

    @data("network_offering", "network_offering_vpcNS")
    @attr(tags=["advanced", "intervlan"])
    def test_02_create_network_fail(self, value):
        """ Test create network in VPC mismatched services (Should fail)
        """
        
        # Validate the following
        # 1. Create VPC Offering by specifying all supported Services
        #    (Vpn,dhcpdns,UserData, SourceNat,Static NAT and PF,LB,NetworkAcl)
        # 2. Create a VPC using the above VPC offering.
        # 3. Create a network offering with guest type=Isolated" that has
        #    one of supported Services(Vpn,dhcpdns,UserData, SourceNat,Static
        #    NAT,LB and PF,LB,NetworkAcl ) provided by VPCVR and conserver
        #    mode is ON
        # 4. Create a VPC using the above VPC offering.
        # 5. Create a network using the network offering created in step2 as
        #    part of this VPC.
        # 6. Network creation should fail

        if (value == "network_offering_vpcNS" and NSconfigured == False):
           self.skipTest('Netscaler not configured: skipping test')


        if (value == "network_offering"):
           vpc_off_list=VpcOffering.list(
                                  self.apiclient,
                                  name='Default VPC offering',
                                  listall=True
                                  )
        else:
           vpc_off_list=VpcOffering.list(
                                  self.apiclient,
                                  name='Default VPC  offering with Netscaler',
                                  listall=True
                                  )
        if isinstance(vpc_off_list, list):
           vpc_off=vpc_off_list[0]
        self.debug("Creating a VPC with offering: %s" % vpc_off.id)
        
        self.services["vpc"]["cidr"] = '10.1.1.1/16'
        vpc = VPC.create(
                         self.apiclient,
                         self.services["vpc"],
                         vpcofferingid=vpc_off.id,
                         zoneid=self.zone.id,
                         account=self.account.name,
                         domainid=self.account.domainid
                         )
        self.validate_vpc_network(vpc)

        #self.services[value]["supportedservices"] = 'SourceNat'
        self.services[value]["serviceProviderList"] = {
                                        "SourceNat": 'VirtualRouter', }

        self.network_offering = NetworkOffering.create(
                                            self.apiclient,
                                            self.services[value],
                                            conservemode=False
                                            )
        # Enable Network offering
        self.network_offering.update(self.apiclient, state='Enabled')
        self.cleanup.append(self.network_offering)

        # Creating network using the network offering created
        self.debug("Creating network with network offering: %s" %
                                                    self.network_offering.id)
        with self.assertRaises(Exception):
            Network.create(
                                self.apiclient,
                                self.services["network"],
                                accountid=self.account.name,
                                domainid=self.account.domainid,
                                networkofferingid=self.network_offering.id,
                                zoneid=self.zone.id,
                                gateway='10.1.1.1',
                                vpcid=vpc.id
                                )
        return

    @data("network_offering", "network_offering_vpcNS") 
    @attr(tags=["advanced", "intervlan"])
    def test_04_create_multiple_networks_with_lb(self, value):
        """ Test create multiple networks with LB service (Should fail)
        """

        # Validate the following
        # 1. Create VPC Offering by specifying all supported Services
        #    (Vpn,dhcpdns,UserData, SourceNat,Static NAT and PF,LB,NetworkAcl)
        # 2. Create a VPC using the above VPC offering
        # 3. Create a network offering with guest type=Isolated that has LB
        #    services Enabled and conserver mode is "ON".
        # 4. Create a network using the network offering created in step3 as
        #    part of this VPC.
        # 5. Create another network using the network offering created in
        #    step3 as part of this VPC

        if (value == "network_offering_vpcNS" and NSconfigured == False):
           self.skipTest('Netscaler not configured: skipping test')


        if (value == "network_offering"):
           vpc_off_list=VpcOffering.list(
                                  self.apiclient,
                                  name='Default VPC offering',
                                  listall=True
                                  )
        else:
           vpc_off_list=VpcOffering.list(
                                  self.apiclient,
                                  name='Default VPC  offering with Netscaler',
                                  listall=True
                                  )
        if isinstance(vpc_off_list, list):
           vpc_off=vpc_off_list[0]
        self.debug("Creating a VPC with offering: %s" % vpc_off.id)

        self.services["vpc"]["cidr"] = '10.1.1.1/16'
        vpc = VPC.create(
                         self.apiclient,
                         self.services["vpc"],
                         vpcofferingid=vpc_off.id,
                         zoneid=self.zone.id,
                         account=self.account.name,
                         domainid=self.account.domainid
                         )
        self.validate_vpc_network(vpc)

        self.network_offering = NetworkOffering.create(
                                            self.apiclient,
                                            self.services[value],
                                            conservemode=False
                                            )
        # Enable Network offering
        self.network_offering.update(self.apiclient, state='Enabled')
        self.cleanup.append(self.network_offering)

        # Creating network using the network offering created
        self.debug("Creating network with network offering: %s" %
                                                    self.network_offering.id)
        network = Network.create(
                                self.apiclient,
                                self.services["network"],
                                accountid=self.account.name,
                                domainid=self.account.domainid,
                                networkofferingid=self.network_offering.id,
                                zoneid=self.zone.id,
                                gateway='10.1.1.1',
                                vpcid=vpc.id
                                )
        self.debug("Created network with ID: %s" % network.id)
        self.debug(
            "Verifying list network response to check if network created?")
        networks = Network.list(
                                self.apiclient,
                                id=network.id,
                                listall=True
                                )
        self.assertEqual(
                         isinstance(networks, list),
                         True,
                         "List networks should return a valid response"
                         )
        nw = networks[0]

        self.assertEqual(
            nw.networkofferingid,
            self.network_offering.id,
            "Network should be created from network offering - %s" %
                                                    self.network_offering.id
             )
        self.assertEqual(
                         nw.vpcid,
                         vpc.id,
                         "Network should be created in VPC: %s" % vpc.name
                         )
        self.debug("Creating another network in VPC: %s" % vpc.name)
        with self.assertRaises(Exception):
            Network.create(
                                self.apiclient,
                                self.services["network"],
                                accountid=self.account.name,
                                domainid=self.account.domainid,
                                networkofferingid=self.network_offering.id,
                                zoneid=self.zone.id,
                                gateway='10.1.2.1',
                                vpcid=vpc.id
                                )
        self.debug(
        "Network creation failed as network with LB service already exists")
        return

    @attr(tags=["intervlan"])
    def test_05_create_network_ext_LB(self):
        """ Test create network with external LB devices
        """

        # Validate the following
        # 1. Create VPC Offering by specifying all supported Services
        #    (Vpn,dhcpdns,UserData, SourceNat,Static NAT and PF,LB,NetworkAcl)
        # 2. Create a VPC using the above VPC offering
        # 3. Create a network offering with guest type=Isolated that has LB
        #    services Enabled and conserver mode is "ON".
        # 4. Create a network using the network offering created in step3 as
        #    part of this VPC.
        # 5. Create another network using the network offering created in
        #    step3 as part of this VPC

        vpc_off_list=VpcOffering.list(
                                  self.apiclient,
                                  name='Default VPC offering',
                                  listall=True
                                  )
        if isinstance(vpc_off_list, list):
           vpc_off=vpc_off_list[0]
        self.debug("Creating a VPC with offering: %s" % vpc_off.id)

        self.services["vpc"]["cidr"] = '10.1.1.1/16'
        vpc = VPC.create(
                         self.apiclient,
                         self.services["vpc"],
                         vpcofferingid=vpc_off.id,
                         zoneid=self.zone.id,
                         account=self.account.name,
                         domainid=self.account.domainid
                         )
        self.validate_vpc_network(vpc)

        #with self.assertRaises(Exception):
        self.network_offering = NetworkOffering.create(
                                                     self.apiclient,
                                                     self.services["network_offering_vpcNS"],
                                                     conservemode=False
                                                     )
        # Enable Network offering
        self.network_offering.update(self.apiclient, state='Enabled')
        self.cleanup.append(self.network_offering)

        # Creating network using the network offering created
        self.debug("Creating network with network offering: %s" %
                                                    self.network_offering.id)
        with self.assertRaises(Exception):
           Network.create(
                      self.apiclient,
                      self.services["network"],
                      accountid=self.account.name,
                      domainid=self.account.domainid,
                      networkofferingid=self.network_offering.id,
                      zoneid=self.zone.id,
                      gateway='10.1.1.1',
                      vpcid=vpc.id
                     )
        self.debug("Network creation failed")
        return

    @unittest.skip("skipped - RvR didn't support VPC currently ")
    @attr(tags=["advanced", "intervlan"])
    def test_06_create_network_with_rvr(self):
        """ Test create network with redundant router capability
        """

        # Validate the following
        # 1. Create VPC Offering by specifying all supported Services
        #    (Vpn,dhcpdns,UserData, SourceNat,Static NAT and PF,LB,NetworkAcl)
        # 2. Create a VPC using the above VPC offering
        # 3. Create a network offering with guest type=Isolated that has all
        #    services provided by VPC VR,conserver mode ""OFF"" and Redundant
        #    Router capability enabled.
        # 4. Create a VPC using the above VPC offering.
        # 5. Create a network using the network offering created in step2 as
        #    part of this VPC

        self.debug("Creating a VPC offering..")
        vpc_off = VpcOffering.create(
                                     self.apiclient,
                                     self.services["vpc_offering"]
                                     )

        self.cleanup.append(vpc_off)
        self.validate_vpc_offering(vpc_off)

        self.debug("Enabling the VPC offering created")
        vpc_off.update(self.apiclient, state='Enabled')

        self.debug("creating a VPC network in the account: %s" %
                                                    self.account.name)
        self.services["vpc"]["cidr"] = '10.1.1.1/16'
        vpc = VPC.create(
                         self.apiclient,
                         self.services["vpc"],
                         vpcofferingid=vpc_off.id,
                         zoneid=self.zone.id,
                         account=self.account.name,
                         domainid=self.account.domainid
                         )
        self.validate_vpc_network(vpc)

        # Enable redundant router capability for the network offering
        self.services["network"]["serviceCapabilityList"] = {
                                                "SourceNat": {
                                                    "RedundantRouter": "true",
                                                    },
                                                }

        self.network_offering = NetworkOffering.create(
                                            self.apiclient,
                                            self.services["network_offering"],
                                            conservemode=False
                                            )
        # Enable Network offering
        self.network_offering.update(self.apiclient, state='Enabled')
        self.cleanup.append(self.network_offering)

        # Creating network using the network offering created
        self.debug("Creating network with network offering: %s" %
                                                    self.network_offering.id)
        with self.assertRaises(Exception):
            Network.create(
                                self.apiclient,
                                self.services["network"],
                                accountid=self.account.name,
                                domainid=self.account.domainid,
                                networkofferingid=self.network_offering.id,
                                zoneid=self.zone.id,
                                gateway='10.1.2.1',
                                vpcid=vpc.id
                                )
        self.debug("Network creation failed")
        return

    @attr(tags=["advanced", "intervlan"])
    def test_07_create_network_unsupported_services(self):
        """ Test create network services not supported by VPC (Should fail)
        """

        # Validate the following
        # 1. Create VPC Offering by specifying supported Services -
        #    Vpn,dhcpdns,UserData, SourceNat,Static NAT and PF,LB,NetworkAcl)
        #    with out including LB services.
        # 2. Create a VPC using the above VPC offering
        # 3. Create a network offering with guest type=Isolated that has all
        #    supported Services(Vpn,dhcpdns,UserData, SourceNat,Static NAT,LB
        #    and PF,LB,NetworkAcl ) provided by VPCVR and conserver mode is OFF
        # 4. Create a VPC using the above VPC offering
        # 5. Create a network using the network offering created in step2 as
        #    part of this VPC.

        self.debug("Creating a VPC offering without LB service")
        self.services["vpc_offering"]["supportedservices"] = 'Dhcp,Dns,SourceNat,PortForwarding,Vpn,UserData,StaticNat'

        vpc_off = VpcOffering.create(
                                     self.apiclient,
                                     self.services["vpc_offering"]
                                     )

        self.cleanup.append(vpc_off)
        self.validate_vpc_offering(vpc_off)

        self.debug("Enabling the VPC offering created")
        vpc_off.update(self.apiclient, state='Enabled')

        self.debug("creating a VPC network in the account: %s" %
                                                    self.account.name)
        self.services["vpc"]["cidr"] = '10.1.1.1/16'
        vpc = VPC.create(
                         self.apiclient,
                         self.services["vpc"],
                         vpcofferingid=vpc_off.id,
                         zoneid=self.zone.id,
                         account=self.account.name,
                         domainid=self.account.domainid
                         )
        self.validate_vpc_network(vpc)

        self.network_offering = NetworkOffering.create(
                                            self.apiclient,
                                            self.services["network_offering"],
                                            conservemode=False
                                            )
        # Enable Network offering
        self.network_offering.update(self.apiclient, state='Enabled')
        self.cleanup.append(self.network_offering)

        # Creating network using the network offering created
        self.debug("Creating network with network offering: %s" %
                                                    self.network_offering.id)
        with self.assertRaises(Exception):
            Network.create(
                                self.apiclient,
                                self.services["network"],
                                accountid=self.account.name,
                                domainid=self.account.domainid,
                                networkofferingid=self.network_offering.id,
                                zoneid=self.zone.id,
                                gateway='10.1.2.1',
                                vpcid=vpc.id
                                )
        self.debug("Network creation failed as VPC doesn't have LB service")
        return

    @attr(tags=["advanced", "intervlan"])
    def test_08_create_network_without_sourceNAT(self):
        """ Test create network without sourceNAT service in VPC (should fail)
        """

        # Validate the following
        # 1. Create VPC Offering by specifying supported Services-
        #    Vpn,dhcpdns,UserData, SourceNat,Static NAT and PF,LB,NetworkAcl)
        #    with out including LB services.
        # 2. Create a VPC using the above VPC offering
        # 3. Create a network offering with guest type=Isolated that does not
        #    have SourceNAT services enabled
        # 4. Create a VPC using the above VPC offering
        # 5. Create a network using the network offering created in step2 as
        #    part of this VPC

        self.debug("Creating a VPC offering without LB service")
        self.services["vpc_offering"]["supportedservices"] = 'Dhcp,Dns,SourceNat,PortForwarding,UserData,StaticNat'

        vpc_off = VpcOffering.create(
                                     self.apiclient,
                                     self.services["vpc_offering"]
                                     )

        self.cleanup.append(vpc_off)
        self.validate_vpc_offering(vpc_off)

        self.debug("Enabling the VPC offering created")
        vpc_off.update(self.apiclient, state='Enabled')

        self.debug("creating a VPC network in the account: %s" %
                                                    self.account.name)
        self.services["vpc"]["cidr"] = '10.1.1.1/16'
        vpc = VPC.create(
                         self.apiclient,
                         self.services["vpc"],
                         vpcofferingid=vpc_off.id,
                         zoneid=self.zone.id,
                         account=self.account.name,
                         domainid=self.account.domainid
                         )
        self.validate_vpc_network(vpc)

        self.debug("Creating network offering without SourceNAT service")
        self.services["network_offering"]["supportedservices"] = 'Dhcp,Dns,PortForwarding,Lb,UserData,StaticNat,NetworkACL'
        self.services["network_offering"]["serviceProviderList"] = {
                                        "Dhcp": 'VpcVirtualRouter',
                                        "Dns": 'VpcVirtualRouter',
                                        "PortForwarding": 'VpcVirtualRouter',
                                        "Lb": 'VpcVirtualRouter',
                                        "UserData": 'VpcVirtualRouter',
                                        "StaticNat": 'VpcVirtualRouter',
                                        "NetworkACL": 'VpcVirtualRouter'
                                        }

        self.debug("Creating network offering without SourceNAT")
        with self.assertRaises(Exception):
            NetworkOffering.create(
                                    self.apiclient,
                                    self.services["network_offering"],
                                    conservemode=False
                                   )
        self.debug("Network creation failed as VPC doesn't have LB service")
        return
    
    @data("network_off_shared", "network_offering_vpcNS")
    @attr(tags=["advanced", "intervlan"])
    def test_09_create_network_shared_nwoff(self, value):
        """ Test create network with shared network offering
        """

        # Validate the following
        # 1. Create VPC Offering by specifying supported Services -
        #    Vpn,dhcpdns,UserData, SourceNat,Static NAT and PF,LB,NetworkAcl)
        #    with out including LB services
        # 2. Create a VPC using the above VPC offering
        # 3. Create a network offering with guest type=shared
        # 4. Create a VPC using the above VPC offering
        # 5. Create a network using the network offering created in step2
        #    as part of this VPC

        if (value == "network_offering_vpcNS" and NSconfigured == False):
           self.skipTest('Netscaler not configured: skipping test')

        if (value == "network_off_shared"):
           vpc_off_list=VpcOffering.list(
                                  self.apiclient,
                                  name='Default VPC offering',
                                  listall=True
                                  )
        else:
           vpc_off_list=VpcOffering.list(
                                  self.apiclient,
                                  name='Default VPC  offering with Netscaler',
                                  listall=True
                                  )
        if isinstance(vpc_off_list, list):
           vpc_off=vpc_off_list[0]
        self.debug("Creating a VPC with offering: %s" % vpc_off.id)

        self.services["vpc"]["cidr"] = '10.1.1.1/16'
        vpc = VPC.create(
                         self.apiclient,
                         self.services["vpc"],
                         vpcofferingid=vpc_off.id,
                         zoneid=self.zone.id,
                         account=self.account.name,
                         domainid=self.account.domainid
                         )
        self.validate_vpc_network(vpc)

        self.debug("Creating network offering with guesttype=shared")

        self.network_offering = NetworkOffering.create(
                                        self.apiclient,
                                        self.services["network_off_shared"],
                                        conservemode=False
                                        )
        # Enable Network offering
        self.network_offering.update(self.apiclient, state='Enabled')
        self.cleanup.append(self.network_offering)

        # Creating network using the network offering created
        self.debug(
            "Creating network with network offering without SourceNAT: %s" %
                                                    self.network_offering.id)
        with self.assertRaises(Exception):
            Network.create(
                                self.apiclient,
                                self.services["network"],
                                accountid=self.account.name,
                                domainid=self.account.domainid,
                                networkofferingid=self.network_offering.id,
                                zoneid=self.zone.id,
                                gateway='10.1.1.1',
                                vpcid=vpc.id
                                )
        self.debug("Network creation failed")
        return

    @data("network_offering", "network_offering_vpcNS")
    @attr(tags=["advanced", "intervlan"])
    def test_10_create_network_with_conserve_mode(self, value):
        """ Test create network with conserve mode ON
        """

        # Validate the following
        # 1. Create VPC Offering by specifying all supported Services
        #    (Vpn,dhcpdns,UserData, SourceNat,Static NAT and PF,LB,NetworkAcl)
        # 2. Create a VPC using the above VPC offering
        # 3. Create a network offering with guest type=Isolated that has all
        #    supported Services(Vpn,dhcpdns,UserData, SourceNat,Static NAT,LB
        #    and PF,LB,NetworkAcl ) provided by VPCVR and conserver mode is ON
        # 4. Create a VPC using the above VPC offering
        # 5. Create a network using the network offering created in step2 as
        #    part of this VPC

        if (value == "network_offering_vpcNS" and NSconfigured == False):
           self.skipTest('Netscaler not configured: skipping test')

        if (value == "network_offering"):
           vpc_off_list=VpcOffering.list(
                                  self.apiclient,
                                  name='Default VPC offering',
                                  listall=True
                                  )
        else:
           vpc_off_list=VpcOffering.list(
                                  self.apiclient,
                                  name='Default VPC  offering with Netscaler',
                                  listall=True
                                  )
        if isinstance(vpc_off_list, list):
           vpc_off=vpc_off_list[0]
        self.debug("Creating a VPC with offering: %s" % vpc_off.id)

        self.services["vpc"]["cidr"] = '10.1.1.1/16'
        vpc = VPC.create(
                         self.apiclient,
                         self.services["vpc"],
                         vpcofferingid=vpc_off.id,
                         zoneid=self.zone.id,
                         account=self.account.name,
                         domainid=self.account.domainid
                         )
        self.validate_vpc_network(vpc)

        self.debug("Creating network offering with conserve mode = ON")

        with self.assertRaises(Exception):
            NetworkOffering.create(
                                    self.apiclient,
                                    self.services[value],
                                    conservemode=True
                                 )
        self.debug(
        "Network creation failed as VPC support nw with conserve mode OFF")
        return
