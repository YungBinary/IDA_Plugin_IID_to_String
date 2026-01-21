"""
Author: x.com/YungBinary
Description: IDA plugin that supports right click of an IID + commenting with string,
            highlight IID start address -> right click -> IID to String
"""
  
import ida_bytes
import struct
import uuid
import idaapi
import idc
import idautils
import ida_kernwin
import base64


def PLUGIN_ENTRY():
    """
    Entrypoint, return instance of iid_to_string_plugin class
    """
    return iid_to_string_plugin()


class IIDToStringHandler(idaapi.action_handler_t):
    """
    Handler class used in action registration
    """

    def __init__(self, action_function):
        idaapi.action_handler_t.__init__(self)
        self.action_function = action_function

    def activate(self, ctx):
        """
        Call callback function when invoked
        """
        self.action_function()
        return 1

    def update(self, ctx):
        """
        This action is always available
        """
        return idaapi.AST_ENABLE_ALWAYS


class Hooks(idaapi.UI_Hooks):
    def populating_widget_popup(self, widget, popup_handle):
        attach_action(widget, popup_handle, idaapi.get_widget_type(widget))
        pass


def iid_to_string_callback():
    """
    Convert IID to string, add comments where it is referenced
    """

    ea = idc.get_screen_ea()
    memory_address = hex(ea)
    num_bytes = ida_bytes.get_item_size(ea)
    # Verify item is 16 bytes
    assert num_bytes == 16, "Not a valid IID as it is not 16 bytes..."
    guid_bytes = ida_bytes.get_bytes(ea, num_bytes)
    # Create UUID from bytes
    guid = uuid.UUID(bytes_le=guid_bytes)
    print(f"Converted IID at {memory_address} to string: {str(guid)}")
    # Set comment for address of IID
    idaapi.set_cmt(ea, str(guid), False)
    # Set comments at addresses that have references to IID
    for xref in idautils.XrefsTo(ea, 0):
        from_ea = xref.frm
        idaapi.set_cmt(from_ea, str(guid), False)


class iid_to_string_plugin(idaapi.plugin_t):

    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    wanted_name = "IID to String"

    def init(self):
        """
        This function is called by IDA
        """
        # Register the IID to String action
        self._register_action()
        # Listen for UI notification and use attach_action_to_popup function
        self._install_hooks()
        return idaapi.PLUGIN_KEEP


    def term(self):
        """
        This function is called by IDA when it exits
        """
        self._hooks.unhook()
        self._unregister_action()


    def _install_hooks(self):
        """
        Install plugin hooks into IDA
        """
        self._hooks = Hooks()
        self._hooks.hook()


    ACTION_IID_TO_STRING  = "iid_to_string"


    def _register_action(self):
        """
        Register action with IDA
        """

        # Describe the action
        icon_data = base64.b64decode(
            """iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAMAAAAoLQ9TAAABlVBMVEVHcEwiT4V
            BVns1OFM+aZpriaxZdppQb5VeTkJcgqyUd016m74hS31jdIV1b19QcpmXXDRHZ5CcX
            DGRdl+mYTOjWStaJRmOSyZHJB6LYjdPZX2EakY6Y5TEfkGScEGTbDhaLyRLIBtoaHM
            3Xo1mQT8/FxiJUzM8U3ppi6+EclmhgVOmcTd0k7WKgW99aEr3hQCRcUZfYGehglIiS
            3w8OEtvfINCTmkpVop6nMBsZVVzj697b1Xo7/SWn6ujj27EdjiPpsCnlXjO2uS9yNO
            chV+ce0+FeGWliF1igaGpusuDkaePl6G9uKrD0tudYDt2Qjff6fKqWSjIztTM196nw
            diRQh+qrLSlvdLAx8uPm60sLDjX4emRjJOQX0VfYWi9wMY5OUSmtsmhg1WssrKzt7i
            9s6yVe1p4j6aDpMeoeFSvXy2aSiK6vb5id5e5ajJMbZRdk8Dy9vuwqJW0pY2opp6CM
            RWstb+VlJvJ5/WJTC5Ps+J+V0zEvJqme2zNy7p7vGmHqIrh0IHIqKW+t2Stp2zCj4H
            E1eckzENwAAAAPHRSTlMAN24OZ3FrcQfp5+047fQ3bSvWsenbKKgdRGabXfjhh3o+b
            JnGqNtR+9xyFe3upQQumDUuz6ttPe2O7b1cWPctAAAA+UlEQVQY02NgYGBgFhASERU
            XY4ABfmFZe/usbBV2ZqgAW6Z9XmBoqb+GMiurIEhAyS8w1D+2NjWkwMOBjYFBQkHNr
            7I6Jiw+yNYjP5edgUFR1SSyPC4qISYuISrMiwmoQ9s0xKY1tsEmwja+MNFQn4FBSzf
            cpqml3tfZ2camTNOIgUGeK7miqrkx2ikgINqRy4CBQVLOMTi8ps4pOMjJJ02PA2iIt
            GuxbaStt7dtibubGcgdUm6uPr6enonJdnZgWxhY0t2TiiKcU+1cUhwgAhk5ji4uaUl
            2KW0QARlObh1ePj5eKwtuTnWQADMPDw+jpbU5Iw+PMQcDACroNPUkhYZVAAAAAElFT
            kSuQmCC"""
        )
        act_icon = ida_kernwin.load_custom_icon(data=icon_data, format="png")
        action_desc = idaapi.action_desc_t(
            self.ACTION_IID_TO_STRING,
            "IID to String",
            IIDToStringHandler(iid_to_string_callback),
            None,
            "IID to String",
            act_icon
        )

        # Register the action
        idaapi.register_action(action_desc)


    def _unregister_action(self):
        """
        Unregister action
        """
        idaapi.unregister_action(self.ACTION_IID_TO_STRING)


def attach_action(widget, popup_handle, widget_type):
    """
    Attach action to context menu for disassembly window widget
    """

    if widget_type != idaapi.BWN_DISASMS:
        return

    idaapi.attach_action_to_popup(
        widget,
        popup_handle,
        iid_to_string_plugin.ACTION_IID_TO_STRING,
        "IID to String",
        idaapi.SETMENU_APP
    )
