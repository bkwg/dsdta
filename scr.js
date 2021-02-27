"use strict";

Interceptor.attach(Module.findExportByName(null, "printf"), {
    onEnter: function(args) {
        var str_ptr = new NativePointer(args[0]);
        var str     = str_ptr.readCString();
        var str_len = str.length;
        var data = "printf" + ":" + str_ptr + ":" + str_len
        send(data);
    }
});

Interceptor.attach(Module.findExportByName(null, "puts"), {
    onEnter: function(args) {
        var str_ptr = new NativePointer(args[0]);
        var str     = str_ptr.readCString();
        var str_len = str.length;
        var data = "puts" + ":" + str_ptr + ":" + str_len
        send(data);
    }
});

Interceptor.attach(Module.findExportByName(null, "fgets"), {
    onEnter: function(args) {
        var str_ptr = new NativePointer(args[0]);
        var fd      = args[2];
        var count   = args[1];
    },
   onLeave: function(retval) {
        var ptr = new NativePointer(retval);
        var data = "fgets" + ":" + ptr + ":" + ptr.readCString().length;
        send(data);
   }
});

var malloc_size = 0;
Interceptor.attach(Module.findExportByName(null, "malloc"), {
    onEnter: function(args) {
        malloc_size = args[0];
    },
   onLeave: function(retval) {
        var ptr = new NativePointer(retval);
        var data = "malloc" + ":" + ptr + ":" + malloc_size;
        send(data);
   }
});

var freed_ptr;
Interceptor.attach(Module.findExportByName(null, "free"), {
    onEnter: function(args) {
        freed_ptr = args[0];
        var data = "free" + ":" + freed_ptr + ":" + "0";
        send(data);
    }
});
