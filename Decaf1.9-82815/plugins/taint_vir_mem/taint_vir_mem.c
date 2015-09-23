#include "DECAF_types.h"
#include "DECAF_main.h"
#include "DECAF_callback.h"
#include "DECAF_callback_common.h"
#include "vmi_callback.h"
#include "utils/Output.h"
#include "DECAF_target.h"
#include "tainting/taintcheck_opt.h"

#define BEGIN_ADDR      0xbffff7cc
#define TAINT_SZ        4

//basic stub for plugins
static plugin_interface_t taint_mem_interface;
static DECAF_Handle mem_opera_handle = DECAF_NULL_HANDLE;

static int tainted_flag = 0;
static int taint_addr = 0;
static int taint_sz = 0;

void do_pass_taint_arg(Monitor *mon, const QDict *qdict)
{
    uint32_t mem_addr, mem_size;
    if(qdict != NULL){
        mem_addr = qdict_get_int(qdict, "mem_addr");
        mem_size = qdict_get_int(qdict, "mem_size");
        DECAF_printf("The mem addr: %x and mem_size: %d", mem_addr, mem_size);

        taint_addr = mem_addr;
        taint_sz = mem_size;
    }
}

/*
 * Handler to implement the command taint_guestOS_mem.
 */
void do_taint_memory(int addr, int sz){
//    tainted_flag = 1;
    uint8_t taint_mark = 0xff;
    uint8_t taint_source[sz];
    if(sz != 0){
        memset(taint_source, taint_mark, sz);
        if(taintcheck_taint_virtmem(addr, sz, taint_source) != 0){
            DECAF_printf("Fail to taint guest OS memory!\n");
        } else{
            DECAF_printf("Sucessfully to taint guest OS memory!\n");
            taint_addr = 0;
            taint_sz = 0;
        }
    }
//    memset(taint_source, taint_mark, TAINT_SZ);
//
//    if(taintcheck_taint_virtmem(BEGIN_ADDR, TAINT_SZ, taint_source) != 0){
//        tainted_flag = 0;
//        DECAF_printf("Fail to taint guest OS memory!\n");
//    } else
//        DECAF_printf("Sucessfully to taint guest OS memory!\n");
}

/*
 * This callback is invoked when a new process starts in the guest OS.
 */
static void load_mem_read_callback(DECAF_Callback_Params* param) {
    if(param->mr.vaddr == taint_addr && taint_addr != 0){
        do_taint_memory(taint_addr, taint_sz);
//    if(param->mr.vaddr == BEGIN_ADDR){
//        if(!tainted_flag)
//            do_taint_memory();

//        DECAF_printf("The monitor guest OS memory with virtual addr: %x has "
//                "been read\n", BEGIN_ADDR);
    }
}

static void load_mem_write_callback(DECAF_Callback_Params* param) {
    if(param->mw.vaddr == taint_addr && taint_addr != 0){
        do_taint_memory(taint_addr, taint_sz);
//    if(param->mw.vaddr == BEGIN_ADDR){
//        if(!tainted_flag)
//            do_taint_memory();

//        DECAF_printf("The monitor guest OS memory with virtual addr: %x has "
//                "been read\n", BEGIN_ADDR);
    }
}

static int taint_mem_init(void) {
    DECAF_printf("Taint memory plugin starts...\n");

    //register for process create and process remove events
//    mem_read_handle = DECAF_register_callback(DECAF_MEM_READ_CB,
//            &load_mem_read_callback, NULL);
    mem_opera_handle = DECAF_register_callback(DECAF_MEM_WRITE_CB,
            &load_mem_write_callback, NULL);
    if (mem_opera_handle == DECAF_NULL_HANDLE) {
        DECAF_printf(
                "Could not register for memory operation events\n");
    }
    return (0);
}

/*
 * This function is invoked when the plugin is unloaded.
 */
static void taint_mem_cleanup(void) {
    DECAF_printf("Bye world\n");
    /*
     * Unregister for the taint memory callback and exit
     */
    if(mem_opera_handle != DECAF_NULL_HANDLE) {
        DECAF_unregister_callback(DECAF_MEM_READ_CB, mem_opera_handle);
        mem_opera_handle = DECAF_NULL_HANDLE;
    }
}
/*
 * Commands supported by the plugin. Included in plugin_cmds.h
 */
static mon_cmd_t taint_mem_cmds[] = {
		{
		    .name = "taint_guestOS_mem",
		    .args_type = "",
		    .mhandler.cmd = do_taint_memory,
		    .params = "no params",
		    .help = "Taint a specific memory buffer in guest OS"
		},
		{
		    .name       = "pass_taint_args",
		    .args_type  = "mem_addr:i,mem_size:i",
		    .mhandler.cmd   = do_pass_taint_arg,
		    .params     = "mem_addr mem_size",
		    .help       = "pass the begin addr and size of tainting memory"
		},
		{ NULL, NULL, },
};

/*
 * This function registers the plugin_interface with DECAF.
 * The interface is used to register custom commands, let DECAF know which
 * cleanup function to call upon plugin unload, etc,.
 */
plugin_interface_t* init_plugin(void) {
    taint_mem_interface.mon_cmds = taint_mem_cmds;
    taint_mem_interface.plugin_cleanup = &taint_mem_cleanup;

    taint_mem_init();
    return (&taint_mem_interface);
}
