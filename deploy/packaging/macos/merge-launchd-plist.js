// Run with /usr/bin/osascript -l JavaScript. Uses only macOS Foundation;
// installation does not require Python, Xcode, a shell eval, or GUI automation.
ObjC.import('Foundation');

function readPlist(path) {
    const data = $.NSData.dataWithContentsOfFile(path);
    if (!data) throw new Error('Cannot read plist');
    const error = Ref();
    const value = $.NSPropertyListSerialization.propertyListWithDataOptionsFormatError(data, 0, null, error);
    if (!value) throw new Error('Cannot decode plist');
    return ObjC.deepUnwrap(value);
}

function merge(prior, generated, forceNoAutoUpdate) {
    const oldArgs = prior.ProgramArguments;
    const newArgs = generated.ProgramArguments;
    function stringArray(value) {
        return Array.isArray(value) && value.length > 0 && value.every(x => typeof x === 'string');
    }
    if (!stringArray(oldArgs) || !stringArray(newArgs)) throw new Error('Invalid ProgramArguments');
    const fixed = ['--plugin-dir', '--data-dir', '--log-file', '--log-max-size', '--log-max-files'];
    const signing = ['--plugin-trust-bundle', '--plugin-require-signature'];
    const generatedSigning = newArgs.indexOf('--plugin-trust-bundle') >= 0;
    const preserved = [];
    for (let index = 1; index < oldArgs.length;) {
        const argument = oldArgs[index];
        const name = argument.split('=', 1)[0];
        const inlineValue = argument.indexOf('=') >= 0;
        if (fixed.indexOf(name) >= 0) {
            index += inlineValue ? 1 : 2;
        } else if (name === '--no-auto-update' && forceNoAutoUpdate) {
            index += 1;
        } else if (generatedSigning && signing.indexOf(name) >= 0) {
            index += name === '--plugin-trust-bundle' && !inlineValue ? 2 : 1;
        } else {
            preserved.push(argument);
            index += 1;
        }
    }
    generated.ProgramArguments = newArgs.concat(preserved);
    const allowed = ['YUZU_SERVER', 'YUZU_CA_CERT', 'YUZU_TLS_SYSTEM_ROOTS', 'YUZU_CLIENT_CERT',
        'YUZU_CLIENT_KEY', 'YUZU_CERT_STORE', 'YUZU_CERT_SUBJECT', 'YUZU_CERT_THUMBPRINT',
        'YUZU_PLUGIN_ALLOWLIST', 'YUZU_PLUGIN_TRUST_BUNDLE', 'YUZU_PLUGIN_REQUIRE_SIGNATURE'];
    const oldEnvironment = prior.EnvironmentVariables === undefined ? {} : prior.EnvironmentVariables;
    if (!oldEnvironment || Array.isArray(oldEnvironment) || typeof oldEnvironment !== 'object' ||
        !Object.keys(oldEnvironment).every(key => typeof oldEnvironment[key] === 'string')) {
        throw new Error('Invalid EnvironmentVariables');
    }
    const retained = {};
    allowed.forEach(key => {
        if (Object.prototype.hasOwnProperty.call(oldEnvironment, key) &&
            !(generatedSigning && (key === 'YUZU_PLUGIN_TRUST_BUNDLE' || key === 'YUZU_PLUGIN_REQUIRE_SIGNATURE'))) {
            retained[key] = oldEnvironment[key];
        }
    });
    if (Object.keys(retained).length) generated.EnvironmentVariables = retained;
    else delete generated.EnvironmentVariables;
    return generated;
}

function run(argv) {
    let previous, destination, force = false;
    for (let index = 0; index < argv.length; index++) {
        if (argv[index] === '--previous') previous = argv[++index];
        else if (argv[index] === '--destination') destination = argv[++index];
        else if (argv[index] === '--force-no-auto-update') force = true;
        else throw new Error('Unknown argument');
    }
    if (!previous || !destination) throw new Error('Previous and destination plist paths required');
    const result = merge(readPlist(previous), readPlist(destination), force);
    const error = Ref();
    const data = $.NSPropertyListSerialization.dataWithPropertyListFormatOptionsError(
        $(result), $.NSPropertyListXMLFormat_v1_0, 0, error);
    if (!data || !data.writeToFileAtomically(destination, true)) throw new Error('Cannot write merged plist');
}
