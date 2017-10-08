const fs = require('fs');
const {addIdentityProvider, providers} = require('./providers');
const {ServiceProvider} = require('samlify');

let sp;

function init(privateKeyFilepath, metadataFilepath) {
    sp = ServiceProvider({
        privateKey: fs.readFileSync(privateKeyFilepath),
        metadata: fs.readFileSync(metadataFilepath),
    });

    return true;
}

function loginRequest(idpKey, type = 'post') {
    const idp = providers.get(idpKey);

    if (!idp) {
        throw new Error(`Missing Identity Provider with key: ${idpKey}`);
    }

    return sp.createLoginRequest(idp, type);
}

function parseResponse(req, idpKey, type = 'post') {
    const idp = providers.get(idpKey);

    if (!idp) {
        return Promise.reject(`Missing Identity Provider with key: ${idpKey}`);
    }

    return sp.parseLoginResponse(idp, type, req);
}

module.exports = {
    init,
    addIdentityProvider,
    loginRequest,
    parseResponse,
};
