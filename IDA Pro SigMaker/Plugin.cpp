#include "Plugin.h"
#include "Version.h"

plugin_t PLUGIN = {
	IDP_INTERFACE_VERSION,
	PLUGIN_MULTI,
	init,
	nullptr,
	nullptr,
	PLUGIN_NAME " v" PLUGIN_VERSION " for IDA Pro 9.0",
	"Select location in disassembly and press CTRL+ALT+S to open menu",
	PLUGIN_NAME,
	"Ctrl-Alt-S"
};
