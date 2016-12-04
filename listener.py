import logging
from pynput.mouse import Listener as mouseListener
from pynput.mouse import Button


class Listener:
    def __init__(self, local_subnet):
        self._local_subnet = local_subnet

    def on_mouse_click(self, mouse_x, mouse_y, button, pressed):
        if button == Button.right:
            print 1
            # Create some broadcast message here
        if not pressed:
            return False

    def start_mouse_listener(self):
        with mouseListener(
                on_move=None,
                on_click=self.on_mouse_click,
                on_scroll=None) as listener:
            listener.join()
