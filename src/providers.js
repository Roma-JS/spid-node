const fs = require('fs');
const path = require('path');
const {IdentityProvider} = require('samlify');
const providersData = require('./providers.json');

const providers = new Map();

providersData.forEach(provider => {
    const metadata = fs.readFileSync(
        path.resolve(__dirname, '..', 'metadata', `${provider.id}.xml`),
    );

    addIdentityProvider(provider.id, {metadata});
});

function addIdentityProvider(id, configs) {
    // TODO: Check if it's already in map
    const idp = IdentityProvider(configs);

    providers.set(id, idp);
}

module.exports = {
    providers,
    addIdentityProvider,
};
