// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// TPM application object (src/app.cc).
var app = {};

// TPM simulator: wraps src/simulator.cc static functions.
var sim = {};

// TPM util: wraps src/util.cc static functions.
var util = {};

// Log verbosity level.
var logging_level = 2;

// Adds log message to logs output window.
// This function is called from the WASM code (src/log.cc).
function LogMessage(level, msg) {
    if (level <= logging_level) {
        $("#textarea_logs")
            .append(msg)
            .animate({
                    scrollTop: $("#textarea_logs")[0].scrollHeight - $("#textarea_logs").height()
                },
                80);
    }
}

function StringToStdVector(str) {
    var v = new Module.StdVectorOfBytes();
    for (var ch of str) {
        v.push_back(ch.charCodeAt());
    }
    return v;
}

function ByteArrayToStdVector(bytes) {
    var v = new Module.StdVectorOfBytes();
    for (var i in bytes) {
        v.push_back(bytes[i]);
    }
    return v;
}


function StdVectorToByteArray(v) {
    var bytes = [];
    for (var i = 0; i < v.size(); i++) {
        bytes.push(v.get(i));
    }
    return bytes;
}

function ByteArrayToBigInt(bytes) {
    var bn = BigInt(0);
    for (var i in bytes) {
        bn <<= BigInt(8);
        bn += BigInt(bytes[i]);
    }
    return bn;
}

function ByteArrayToBigIntStr(bytes) {
    return "0x" + ByteArrayToBigInt(bytes).toString(16);
}

function BigIntToByteArray(bn) {
    var bytes = [];
    while (bn > 0) {
        bytes.push(parseInt(bn & BigInt(0xFF)));
        bn >>= BigInt(8);
    }
    bytes.reverse();
    return bytes;
}

function BigIntStrToByteArray(str) {
    return BigIntToByteArray(BigInt(str));
}

function ByteArrayToForgeBuffer(bytes) {
    var buffer = forge.util.createBuffer();
    for (var i in bytes) {
        buffer.putByte(bytes[i]);
    }
    return buffer;
}


function HexdumpByteArray(bytes) {
    var res = "";
    for (var i = 0; i < bytes.length; i++) {
        res += bytes[i].toString(16).padStart(2, "0");
    }
    return res;
}


// Helper function for bootstrap-table.
// See "data-formatter" attribute in <table> definitions.
function ShortHexFormatter(v) {
    return "<span style='font-family:monospace;'" +
        " data-toggle='tooltip' title=" + v + ">" + v.substring(0, 16) +
        "...</span>";
}

function ShowPage(page_id) {
    $(".page").hide();
    $(".nav-sidebar > li").removeClass("active");
    var page = $("#" + page_id)
    page.show();
    var side = $("#side_" + page_id)
    side.addClass("active");
}

//
// Simulator window functions.
//
function SetPowerStatuIcon(el, is_on) {
    if (is_on) {
        el.removeClass("glyphicon-remove-sign").addClass("glyphicon-ok-sign");
    } else {
        el.removeClass("glyphicon-ok-sign").addClass("glyphicon-remove-sign");
    }
}

function RefreshPcrTable() {
    var data = [];
    for (var pcr = 0; pcr < 4; pcr++) {
        data.push({
            "pcr": pcr,
            "value": HexdumpByteArray(sim.GetPcr(pcr))
        });
    }
    $("#table_pcrs").bootstrapTable("load", data);
}

function RefreshSeedsTable() {
    var data = [{
        "hierarchy": "Endorsement",
        "value": HexdumpByteArray(sim.GetEndorsementSeed())
    }, {
        "hierarchy": "Platform",
        "value": HexdumpByteArray(sim.GetPlatformSeed())
    }, {
        "hierarchy": "Owner",
        "value": HexdumpByteArray(sim.GetOwnerSeed())
    }, {
        "hierarchy": "Null",
        "value": HexdumpByteArray(sim.GetNullSeed())
    }, ];
    $("#table_seeds").bootstrapTable("load", data);
}

function RefreshSimulatorWindow() {
    SetPowerStatuIcon($("#icon_powered"), sim.IsPoweredOn());
    SetPowerStatuIcon($("#icon_manufactured"), sim.IsManufactured());
    SetPowerStatuIcon($("#icon_started"), sim.IsStarted());
    $("#boot_counter").text(sim.GetBootCounter());
    RefreshPcrTable();
    RefreshSeedsTable();
}

function ShowSeedsWindow() {
    $("#window_seeds").show();
    $("#check_window_seeds").prop("checked", true);
}

function ShowPCRsWindow() {
    $("#window_pcrs").show();
    $("#check_window_pcrs").prop("checked", true);
}

$(document).ready(function() {
    // Initialize bootstrap tables.
    $("#table_pcrs").bootstrapTable({});
    $("#table_seeds").bootstrapTable({});

    // Reload page at given location.
    if (location.hash != "") {
        ShowPage(location.hash.substring(1));
    }

    $("a.self").click(function(event) {
        event.preventDefault();
        var url = $(this).attr("href");
        window.location.href = url;
        ShowPage(url.substring(1));
    });


    // Process system menu action.
    $("#system_actions").on("click", "li", function(event) {
        event.preventDefault();
        var action = $(event.target).attr("data-value");
        switch (action) {
            case "restart":
                app.Shutdown();
                sim.PowerOff();
                sim.PowerOn();
                app.Startup();
                break;

            case "clear":
                app.Clear();
                app.Shutdown();
                sim.PowerOff();
                sim.PowerOn();
                app.Startup();
                break;

            case "manufacture_reset":
                sim.PowerOff();
                sim.PowerOn();
                sim.ManufactureReset();
                sim.PowerOff();
                sim.PowerOn();
                app.Startup();
                break;

            default:
                console.log("Unknown action", action);
        }
        RefreshSimulatorWindow();
    });

    // Process view menu action.
    $("#view_actions").on("click", "li", function(event) {
        event.preventDefault();
        var action = $(event.target).attr("data-value");
        if (action.startsWith("view_")) {
            var id = action.substring(5);
            // Toggle window.
            var win = $("#" + id);
            win.toggle();
            // Flip checkbox
            var checkbox = $("#check_" + id);
            checkbox.prop("checked", !checkbox.prop("checked"));
        } else if (action == "toggle_verbose_logs") {
            // Flip checkbox
            var checkbox = $("#check_verbose_logs");
            checkbox.prop("checked", !checkbox.prop("checked"));
            // Set logging level.
            if (checkbox.prop("checked")) {
                logging_level = 2;
            } else {
                logging_level = 1;
            }
        } else if (action == "clear_logs") {
            $("#textarea_logs").text("");
        } else {
            console.log("Unknown action", action);
        }
    });

    // Sidebar navigation.
    $(".nav-sidebar,.pager").on("click", "li", function(event) {
        event.preventDefault();
        var page_id = $(event.target).attr("data-value");
        window.location.href = "#" + page_id;
        ShowPage(page_id);
    });

    // Execute code in code_cell elements.
    $(".code_cell > .row > .col-md-12 > button").on("click", function(event) {
        var input_el = $(event.target).parent().parent().parent().find(".input");
        var output_el = $(event.target).parent().parent().parent().find(".output");
        var output = [];
        output_el.text("...");
        $.when().then(function() {
            try {
                var print = function() {
                    var args = []
                    for (var i in arguments) {
                        if (typeof(arguments[i]) == 'string' || arguments[i] instanceof String) {
                            args.push(arguments[i]);
                        } else {
                            args.push(JSON.stringify(arguments[i]));
                        }
                    }
                    output.push(args.join(" "));
                };
                output.push(JSON.stringify(eval(input_el.text())));
            } catch (e) {
                if (e instanceof Error) {
                    output.push(e.stack);
                } else if (typeof(e) === 'string' || e instanceof String) {
                    output.push(e);
                } else {
                    output.push(JSON.stringify(e));
                }
            }
            output_el.text(output.join("\n"));
            output_el.removeClass('prettyprinted');
            PR.prettyPrint();
        });
    })

    Module.onRuntimeInitialized = function() {
        console.log("WASM runtime initialized. Creating global objects");
        app = new Module.App();


        //
        // Decorate wasm functions: change return types to simper, native js types.
        //
        app.GetRandom = function(wrapped) {
            return function() {
                const result = wrapped.apply(this, arguments);
                return StdVectorToByteArray(result);
            }
        }(app.GetRandom);

        app.CreatePrimary = function(wrapped) {
            return function() {
                // Function signature:
                //
                // CreatePrimaryResult CreatePrimary(int hierarchy, int type, int restricted,
                //                                   int decrypt, int sign,
                //                                   const std::string &unique,
                //                                   const std::string &user_auth,
                //                                   const std::string &sensitive_data,
                //                                   const std::vector<uint8_t> &auth_policy);
                //
                // Add extra default arguments to match signature.
                if (arguments.length == 0) {
                    [].push.call(arguments, /*hierarchy=*/ TPM2_RH_OWNER);
                }
                if (arguments.length == 1) {
                    [].push.call(arguments, /*type=*/ TPM2_ALG_RSA);
                }
                if (arguments.length == 2) {
                    [].push.call(arguments, /*restricted=*/ 1);
                }
                if (arguments.length == 3) {
                    [].push.call(arguments, /*decrypt=*/ 1);
                }
                if (arguments.length == 4) {
                    [].push.call(arguments, /*sign=*/ 0);
                }
                if (arguments.length == 5) {
                    [].push.call(arguments, /*unique=*/ "");
                }
                if (arguments.length == 6) {
                    [].push.call(arguments, /*user_auth=*/ "");
                }
                if (arguments.length == 7) {
                    [].push.call(arguments, /*sensitive_data=*/ "");
                }
                if (arguments.length == 8) {
                    [].push.call(arguments, /*auth_policy=*/ StringToStdVector(""));
                }
                const result = wrapped.apply(this, arguments);
                result.rsa_public_n = ByteArrayToBigIntStr(StdVectorToByteArray(result.rsa_public_n));
                result.ecc_public_x = ByteArrayToBigIntStr(StdVectorToByteArray(result.ecc_public_x));
                result.ecc_public_y = ByteArrayToBigIntStr(StdVectorToByteArray(result.ecc_public_y));
                result.name = StdVectorToByteArray(result.name);
                result.parent_name = StdVectorToByteArray(result.parent_name);
                result.parent_qualified_name = StdVectorToByteArray(result.parent_qualified_name);
                return result;
            }
        }(app.CreatePrimary);

        app.CreatePrimaryEndorsementKey = function(wrapped) {
            return function() {
                const result = wrapped.apply(this, arguments);
                result.rsa_public_n = ByteArrayToBigIntStr(StdVectorToByteArray(result.rsa_public_n));
                result.ecc_public_x = ByteArrayToBigIntStr(StdVectorToByteArray(result.ecc_public_x));
                result.ecc_public_y = ByteArrayToBigIntStr(StdVectorToByteArray(result.ecc_public_y));
                result.name = StdVectorToByteArray(result.name);
                result.parent_name = StdVectorToByteArray(result.parent_name);
                result.parent_qualified_name = StdVectorToByteArray(result.parent_qualified_name);
                return result;
            }
        }(app.CreatePrimaryEndorsementKey);

        app.Create = function(wrapped) {
            return function() {
                // Function signature:
                //
                // CreateResult Create(uint32_t parent_handle, int type, int restricted,
                //                     int decrypt, int sign, const std::string &user_auth,
                //                     const std::string &sensitive_data,
                //                     const std::vector<uint8_t> &auth_policy);
                //
                // Add extra default arguments to match signature.
                if (arguments.length == 1) {
                    [].push.call(arguments, /*type=*/ TPM2_ALG_RSA);
                }
                if (arguments.length == 2) {
                    [].push.call(arguments, /*restricted=*/ 1);
                }
                if (arguments.length == 3) {
                    [].push.call(arguments, /*decrypt=*/ 0);
                }
                if (arguments.length == 4) {
                    [].push.call(arguments, /*sign=*/ 1);
                }
                if (arguments.length == 5) {
                    [].push.call(arguments, /*user_auth=*/ "");
                }
                if (arguments.length == 6) {
                    [].push.call(arguments, /*sensitive_data=*/ "");
                }
                if (arguments.length == 7) {
                    [].push.call(arguments, /*auth_policy=*/ StringToStdVector(""));
                }
                const result = wrapped.apply(this, arguments);
                // Don't change tpm2b types.
                // result.tpm2b_private = StdVectorToByteArray(result.tpm2b_private);
                // result.tpm2b_public = StdVectorToByteArray(result.tpm2b_public);
                result.rsa_public_n = ByteArrayToBigIntStr(StdVectorToByteArray(result.rsa_public_n));
                result.ecc_public_x = ByteArrayToBigIntStr(StdVectorToByteArray(result.ecc_public_x));
                result.ecc_public_y = ByteArrayToBigIntStr(StdVectorToByteArray(result.ecc_public_y));
                result.parent_name = StdVectorToByteArray(result.parent_name);
                result.parent_qualified_name = StdVectorToByteArray(result.parent_qualified_name);
                return result;
            }
        }(app.Create);

        app.Load = function(wrapped) {
            return function() {
                const result = wrapped.apply(this, arguments);
                result.name = StdVectorToByteArray(result.name);
                return result;
            }
        }(app.Load);

        app.Decrypt = function(wrapped) {
            return function() {
                arguments[1] = jQuery.extend(true, {}, arguments[1]); // deep-copy buffer.
                arguments[1] = ByteArrayToStdVector(arguments[1]);
                const result = wrapped.apply(this, arguments);
                return StdVectorToByteArray(result);
            }
        }(app.Decrypt);

        app.Encrypt = function(wrapped) {
            return function() {
                arguments[1] = jQuery.extend(true, {}, arguments[1]); // deep-copy buffer.
                arguments[1] = ByteArrayToStdVector(arguments[1]);
                const result = wrapped.apply(this, arguments);
                return StdVectorToByteArray(result);
            }
        }(app.Encrypt);

        app.Sign = function(wrapped) {
            return function() {
                const result = wrapped.apply(this, arguments);
                result.rsa_ssa_sig = StdVectorToByteArray(result.rsa_ssa_sig);
                result.ecdsa_r = ByteArrayToBigIntStr(StdVectorToByteArray(result.ecdsa_r));
                result.ecdsa_s = ByteArrayToBigIntStr(StdVectorToByteArray(result.ecdsa_s));
                return result;
            }
        }(app.Sign);

        app.VerifySignature = function(wrapped) {
            return function() {
                arguments[2] = jQuery.extend(true, {}, arguments[2]); // deep-copy SignResult.
                arguments[2].rsa_ssa_sig = ByteArrayToStdVector(arguments[2].rsa_ssa_sig);
                arguments[2].ecdsa_r = ByteArrayToStdVector(BigIntStrToByteArray(arguments[2].ecdsa_r));
                arguments[2].ecdsa_s = ByteArrayToStdVector(BigIntStrToByteArray(arguments[2].ecdsa_s));
                const result = wrapped.apply(this, arguments);
                return result;
            }
        }(app.VerifySignature);

        app.RSADecrypt = function(wrapped) {
            return function() {
                arguments[1] = jQuery.extend(true, {}, arguments[1]); // deep-copy buffer.
                arguments[1] = ByteArrayToStdVector(arguments[1]);
                const result = wrapped.apply(this, arguments);
                return StdVectorToByteArray(result);
            }
        }(app.RSADecrypt);

        app.RSAEncrypt = function(wrapped) {
            return function() {
                arguments[1] = jQuery.extend(true, {}, arguments[1]); // deep-copy buffer.
                arguments[1] = ByteArrayToStdVector(arguments[1]);
                const result = wrapped.apply(this, arguments);
                return StdVectorToByteArray(result);
            }
        }(app.RSAEncrypt);

        app.NvRead = function(wrapped) {
            return function() {
                const result = wrapped.apply(this, arguments);
                result.data = StdVectorToByteArray(result.data);
                return result;
            }
        }(app.NvRead);

        app.Quote = function(wrapped) {
            return function() {
                const result = wrapped.apply(this, arguments);
                result.rsa_ssa_sig = StdVectorToByteArray(result.rsa_ssa_sig);
                result.tpm2b_attest = StdVectorToByteArray(result.tpm2b_attest);
                return result;
            }
        }(app.Quote);


        app.Unseal = function(wrapped) {
            return function() {
                const result = wrapped.apply(this, arguments);
                result.sensitive_data = StdVectorToByteArray(result.sensitive_data);
                return result;
            }
        }(app.Unseal);

        app.PolicyGetDigest = function(wrapped) {
            return function() {
                const result = wrapped.apply(this, arguments);
                return StdVectorToByteArray(result);
            }
        }(app.PolicyGetDigest);

        app.Import = function(wrapped) {
            return function() {
                arguments[2] = jQuery.extend(true, [], arguments[2]); // deep-copy integrity_hmac.
                arguments[2] = StringToStdVector(arguments[2]);
                arguments[3] = jQuery.extend(true, [], arguments[3]); // deep-copy encrypted_private.
                arguments[3] = StringToStdVector(arguments[3]);
                arguments[4] = jQuery.extend(true, [], arguments[4]); // deep-copy encrypted_seed.
                arguments[4] = StringToStdVector(arguments[4]);
                const result = wrapped.apply(this, arguments);
                // Don't change tpm2b types.
                // result.tpm2b_private = StdVectorToByteArray(result.tpm2b_private);
                // result.tpm2b_public = StdVectorToByteArray(result.tpm2b_public);
                return result;
            }
        }(app.Import);

        Module.SimGetPcr = function(wrapped) {
            return function() {
                const result = wrapped.apply(this, arguments);
                return StdVectorToByteArray(result);
            }
        }(Module.SimGetPcr);

        Module.SimGetEndorsementSeed = function(wrapped) {
            return function() {
                const result = wrapped.apply(this, arguments);
                return StdVectorToByteArray(result);
            }
        }(Module.SimGetEndorsementSeed);

        Module.SimGetPlatformSeed = function(wrapped) {
            return function() {
                const result = wrapped.apply(this, arguments);
                return StdVectorToByteArray(result);
            }
        }(Module.SimGetPlatformSeed);

        Module.SimGetOwnerSeed = function(wrapped) {
            return function() {
                const result = wrapped.apply(this, arguments);
                return StdVectorToByteArray(result);
            }
        }(Module.SimGetOwnerSeed);

        Module.SimGetNullSeed = function(wrapped) {
            return function() {
                const result = wrapped.apply(this, arguments);
                return StdVectorToByteArray(result);
            }
        }(Module.SimGetNullSeed);

        Module.UtilUnmarshalAttestBuffer = function(wrapped) {
            return function() {
                arguments[0] = jQuery.extend(true, {}, arguments[0]); // deep-copy tpm2b_attest.
                arguments[0] = ByteArrayToStdVector(arguments[0]);
                const result = wrapped.apply(this, arguments);
                result.signer_qualified_name = StdVectorToByteArray(result.signer_qualified_name);
                result.nonce = StdVectorToByteArray(result.nonce);
                result.selected_pcr_digest = StdVectorToByteArray(result.selected_pcr_digest);
                return result;
            }
        }(Module.UtilUnmarshalAttestBuffer);

        Module.UtilKDFa = function(wrapped) {
            return function() {
                arguments[1] = jQuery.extend(true, [], arguments[1]); // deep-copy key.
                arguments[1] = StringToStdVector(arguments[1]);
                //arguments[3] = jQuery.extend(true, [], arguments[3]); // deep-copy context_u.
                //arguments[3] = StringToStdVector(arguments[3]);
                arguments[4] = jQuery.extend(true, [], arguments[4]); // deep-copy context_v.
                arguments[4] = StringToStdVector(arguments[4]);
                const result = wrapped.apply(this, arguments);
                return StdVectorToByteArray(result);
            }
        }(Module.UtilKDFa);

        // Automatically refresh simulator window after Startup.
        // This simplifies our code snippets.
        app.Startup = function(wrapped) {
            return function() {
                const result = wrapped.apply(this, arguments);
                RefreshSimulatorWindow();
                return result;
            }
        }(app.Startup);

        // Automatically refresh simulator window after ExtendPcr.
        // This simplifies our code snippets.
        app.ExtendPcr = function(wrapped) {
            return function() {
                const result = wrapped.apply(this, arguments);
                RefreshSimulatorWindow();
                return result;
            }
        }(app.ExtendPcr);

        // Copy simulator functions to sim object for easier access.
        // sim.XXXX = Module.SimXXXX
        for (var name in Module) {
            if (name.startsWith("Sim")) {
                sim[name.substring(3)] = Module[name];
            }
        }

        // Copy util functions to util object for easier access.
        // util.XXXX = Module.UtilXXXX
        for (var name in Module) {
            if (name.startsWith("Util")) {
                util[name.substring(4)] = Module[name];
            }
        }

        //
        // Run TPM initialization sequence.
        //
        console.log("Initializing TPM");
        sim.PowerOn();
        sim.ManufactureReset();
        app.Startup();
        var properties = app.GetTpmProperties();
        $("#simulator_version")
            .text(properties.manufacturer_id + "v" + properties.spec_version)
        RefreshSimulatorWindow();
    };
})
