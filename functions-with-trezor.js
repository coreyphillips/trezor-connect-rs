import TrezorConnectModule from 'npm:@trezor/connect';
import { readLines } from "https://deno.land/std/io/read_lines.ts";

const TrezorConnect = TrezorConnectModule.default;

let initialized = false;

TrezorConnect.manifest({
    email: 'developer@xyz.com',
    appUrl: 'http://your.application.com',
});

async function initTrezor() {
    if (initialized) {
        console.log(JSON.stringify({ success: true, message: "Already initialized" }));
        return;
    }

    console.error('⏳ Waiting for you to confirm on the Trezor device…');

    try {
        await TrezorConnect.init();
        initialized = true;
        console.log(JSON.stringify({ success: true }));
    } catch (err) {
        console.log(JSON.stringify({ success: false, error: err.message || String(err) }));
    }
}

async function getPublicKey(path, coin) {
    if (!initialized) {
        console.log(JSON.stringify({ success: false, error: "Not initialized. Run 'init' first." }));
        return;
    }

    console.error('⏳ Waiting for you to confirm the public‑key request on device…');

    try {
        const res = await TrezorConnect.getPublicKey({ path, coin });
        console.log(JSON.stringify(res));
    } catch (err) {
        console.log(JSON.stringify({ success: false, error: err.message || String(err) }));
    }
}

async function getAddress(path, coin, showOnTrezor = true) {
    if (!initialized) {
        console.log(JSON.stringify({ success: false, error: "Not initialized. Run 'init' first." }));
        return;
    }

    console.error('⏳ Waiting for address from device…');

    try {
        const res = await TrezorConnect.getAddress({
            path,
            coin,
            showOnTrezor
        });
        console.log(JSON.stringify(res));
    } catch (err) {
        console.log(JSON.stringify({ success: false, error: err.message || String(err) }));
    }
}

async function closeConnection() {
    if (initialized) {
        try {
            // The disconnect method might not be available in all versions
            // Check if it exists before calling
            if (typeof TrezorConnect.disconnect === 'function') {
                await TrezorConnect.disconnect();
            }

            initialized = false;
            console.log(JSON.stringify({ success: true, message: "Connection closed" }));
        } catch (err) {
            console.log(JSON.stringify({ success: false, error: err.message || String(err) }));
        }
    } else {
        console.log(JSON.stringify({ success: true, message: "Not initialized" }));
    }
}

// JSON Command processor
async function processCommand(cmdLine) {
    try {
        const cmdObj = JSON.parse(cmdLine);
        const command = cmdObj.command;

        if (!command) {
            throw new Error('Missing "command" property in JSON');
        }

        switch (command) {
            case 'init':
                await initTrezor();
                break;
            case 'getFeatures':
                if (!initialized) {
                    console.log(JSON.stringify({ success: false, error: "Not initialized. Run 'init' first." }));
                    return;
                }
                const features = await TrezorConnect.getFeatures();
                console.log(JSON.stringify(features));
                break;
            case 'getpk':
                if (!cmdObj.path || !cmdObj.coin) {
                    throw new Error('Missing required properties for getpk: path, coin');
                }
                await getPublicKey(cmdObj.path, cmdObj.coin);
                break;
            case 'getaddr':
                if (!cmdObj.path || !cmdObj.coin) {
                    throw new Error('Missing required properties for getaddr: path, coin');
                }
                const showOnDevice = cmdObj.showOnTrezor !== undefined ? cmdObj.showOnTrezor : true;
                await getAddress(cmdObj.path, cmdObj.coin, showOnDevice);
                break;
            case 'close':
                await closeConnection();
                break;
            case 'exit':
                await closeConnection();
                console.log(JSON.stringify({ success: true, message: "Exiting" }));
                Deno.exit(0);
                break;
            default:
                throw new Error('Unknown command: ' + command);
        }
    } catch (err) {
        let errorMessage = err.message || String(err);
        if (err instanceof SyntaxError) {
            errorMessage = 'Invalid JSON: ' + errorMessage;
        }

        console.log(JSON.stringify({
            success: false,
            error: errorMessage
        }));
    }
}

// Main function - run interactive command line
if (import.meta.main) {
    console.error("Starting persistent Trezor connection. Send JSON commands:");
    console.error(`  {"command": "init"}                                               - Initialize connection`);
    console.error(`  {"command": "getpk", "path": "m/44'/1'/0'/0", "coin": "Testnet"}  - Get public key`);
    console.error(`  {"command": "getaddr", "path": "m/44'/1'/0'/0/0", "coin": "Testnet", "showOnTrezor": true}  - Get address`);
    console.error(`  {"command": "close"}                                              - Close connection`);
    console.error(`  {"command": "exit"}                                               - Exit the program`);

    // Process commands from stdin
    for await (const line of readLines(Deno.stdin)) {
        await processCommand(line);
        console.error("> "); // Command prompt
    }
}