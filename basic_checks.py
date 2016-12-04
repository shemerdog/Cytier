import os
import wmi
import subprocess
import csv
import socket
import requests
from netaddr import IPNetwork


def wmi_check(query_key, query_attribute, expected_result):
    connection = wmi.WMI()
    query = getattr(connection, query_key)
    for item in query():
        requested_value = getattr(item, query_attribute)
        if requested_value == expected_result:
            return 1
    return 0


def system_check(command, expected_result):
    process_object = subprocess.Popen(command, stdout=subprocess.PIPE)
    process_output = process_object.communicate()[0]
    if process_object.returncode:
        if process_output == expected_result:
            return 0
        else:
            return process_output
    else:
        return 1


def environment_variable_check(variable_name, expected_result):
    try:
        return 0 if os.environ[variable_name] == expected_result else 1
    except KeyError:
        return 1


def is_port_open(target_ip_address, port, expected_result):
    target_address_tuple = (target_ip_address, port)
    connection = socket.socket()
    result = connection.connect_ex(target_address_tuple)
    if result == 0:
        connection.close()
    return result == expected_result


def ping_scan(target_ip):
    return "TTL" in system_check("ping " + target_ip, None)


def http_request(target_url, expected_result):
    response = requests.get(target_url)
    return response.status_code == expected_result


def proxy_http_request(target_url, proxies_definition, expected_result):
    response = requests.get(target_url, proxies=proxies_definition)
    return response.status_code == expected_result


def system_info_check(attribute_name, expected_result):
    system_info_output = system_check(["systeminfo", "/FO", "CSV"], expected_result)
    csv_reader = csv.DictReader(system_info_output.split('\r\n'))
    system_info_dictionary = csv_reader.next()
    return 0 if system_info_dictionary[attribute_name] == expected_result else 1


def network_scan(target_addresses, target_ports, protocol, scan_type=None):
    results = {}
    scanner = {
        "tcp": is_port_open,
        "ping": ping_scan
    }

    # transfer subnet to range
    if "/" in target_addresses:
        target_addresses = IPNetwork(target_addresses)
    if scan_type:
        for ip_address in target_addresses:
            results[ip_address] = scanner[scan_type](ip_address)
            # Create some special scan type here - like OS finger printing
        return results

    for ip_address in target_addresses:
        results[ip_address] = {protocol + "_ports": []}
        for port in target_ports:
            # check if port is tuple should create range
            if scanner[protocol](ip_address, port, 0):
                results[ip_address][protocol + "_ports"].append(port)
        return results
