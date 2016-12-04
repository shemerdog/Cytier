import logging
import urllib

import basic_checks
import configuration
import scoring


class Checker:
    def __init__(self, local_subnet):
        self._local_subnet = local_subnet

    @staticmethod
    def is_in_domain():
        logging.info("Checking if node is part of windows domain")
        score = 0
        score += basic_checks.wmi_check("ComputerSystem", "domain", "WORKGROUP") * scoring.IS_IN_DOMAIN_WMI_CHECK_SCORE
        score += basic_checks.system_info_check("domain", "WORKGROUP") * scoring.IS_IN_DOMAIN_COMPUTER_NAME_CHECK_SCORE
        score += basic_checks.environment_variable_check("userdomain", "") * scoring.IS_IN_DOMAIN_ENVIRONMENT_VARIABLE_CHECK_SCORE
        score += basic_checks.environment_variable_check("userdnsdomain", "") * scoring.IS_IN_DOMAIN_ENVIRONMENT_VARIABLE_CHECK_SCORE
        # update score in DB

    @staticmethod
    def is_connected_to_internet():
        logging.info("Checking if node is connected to the internet")
        score = 0

        logging.info("Checking internet connection using ICMP")
        for ip_address in configuration.PING_SERVERS:
            score += basic_checks.system_check(["ping", "-n", "2", ip_address], 0) * scoring.IS_CONNECTED_TO_INTERNET_ICMP_SCORE

        logging.info("Checking internet connection using DNS")
        for domain_name in configuration.TEST_DOMAINS:
            score += basic_checks.system_check(["nslookup", domain_name], " ")
        for dns_server in configuration.DNS_SERVERS:
            score += basic_checks.is_port_open(dns_server, 53, 0)

        logging.info("Checking internet connection using HTTP\S")
        for http_server in configuration.HTTP_SERVERS:
            score += basic_checks.http_request("http://" + http_server + "/", 200)
            score += basic_checks.http_request("https://" + http_server + "/", 200)
            proxies = urllib.getproxies()
            if proxies:
                score += basic_checks.proxy_http_request(http_server, proxies, " ")
            score += basic_checks.is_port_open(http_server, 80, 0)

        return score

    def tcp_scan(self, ports):
        return basic_checks.network_scan(self._local_subnet, ports, "tcp")

    def workstations_scan(self):
        ports = [configuration.WINDOWS_WORKSTATION_PORTS]
        workstations_ip_addresses_list = self.tcp_scan(ports)
        return workstations_ip_addresses_list

    def servers_scan(self):
        ports = []
        ports += configuration.MICROSOFT_AD_DS_PORTS
        ports += configuration.WEB_SERVER_PORTS
        ports += configuration.MAIL_SERVER_PORTS
        ports += configuration.SQL_SERVER_PORTS

        servers_ip_addresses_list = self.tcp_scan(ports)
        # servers_ip_addresses_list += basic_checks.network_scan(self._local_subnet, scan_type="os_fingerprinting")
        return servers_ip_addresses_list

    def printers_scan(self):
        ports = [9100, 6001]
        printers_ip_addresses_list = self.tcp_scan(ports)
        # get printers from sharing option of surrounding devices
        # get printers from local LDAP\ADDS
        return printers_ip_addresses_list

    def devices_in_subnet(self):
        devices = basic_checks.network_scan(self._local_subnet, None, None, "ping")
        workstations = self.workstations_scan()
        printers = self.printers_scan()
        servers = self.servers_scan()

        return {
                "devices": devices,
                "workstations": workstations,
                "printers": printers,
                "servers": servers
                }

    def get_network_interfaces(self):
        print 1
        # get from ipconfig
        # get from systeminfo
        # get from netifaces

    def get_all_usb_devices(self):
        try:
            import usb
            # installed https://sourceforge.net/projects/libusb-win32/files/libusb-win32-releases/1.2.6.0/
            for device in usb.core.find(find_all=True):
                logging.info("Device: %s" % str(device.product))
                logging.info("  idVendor: %d (%s)" % (device.idVendor, hex(device.idVendor)))
                logging.info("  idProduct: %d (%s)" % (device.idProduct, hex(device.idProduct)))
            return True
        except Exception, e:
            logging.info("No device was found to be connected to the interactive terminal: ", e)
            return False

    def current_running_process_list(self):
        # Get from WMI
        # Get from system call
        try:
            processes_list = basic_checks.system_check(["tasklist", "/svc"], True)
            return processes_list
        except Exception, e:
            logging.debug(e)
