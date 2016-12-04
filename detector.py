import logging
import checker
import listener


class Detector(object):
    """The detector class is the first layer where security alerts are being sent to analysis"""

    def __init__(self, init_checker):
        self._init_checker = init_checker
        self._default_subnet = "10.0.0.0/24"
        super(Detector, self).__init__()

    def start_detector(self):
        logging.info("Starting init detector")
        self._init_checker.is_in_domain()
        self._init_checker.is_connected_to_internet()
        self._init_checker.get_all_usb_devices()
        self._init_checker.get_network_interfaces()

    @staticmethod
    def create_new_network_checker(network_subnet):
        logging.info("Creating new checker instance to scan network")
        network_checker = checker.Checker(network_subnet)
        network_checker.devices_in_subnet()

    def create_new_listener(self):
        new_listener = listener.Listener(self._default_subnet)
        new_listener.start_mouse_listener()

