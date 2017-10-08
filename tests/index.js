const fs = require('fs');
const path = require('path');
const {expect} = require('chai');
const SPID = require('../index');

// spid-test is a (fake) identity provider that accepts only post and redirect requests
const SAMLResponseBody = require('./assets/saml-response');

function createResponse(body) {
    return {
        query: {},
        body,
        octectString: '',
    };
}

describe('SPID', function() {
    beforeEach(
        'should have init function with Service Providers parameters as input',
        () => {
            SPID.init(
                path.resolve(__dirname, 'assets/private-key'),
                path.resolve(__dirname, 'assets/metadata-sp.xml')
            );
        }
    );

    beforeEach('should allow to add new Identity Provider', () => {
        SPID.addIdentityProvider('spid-test', {
            metadata: fs.readFileSync(
                path.resolve(__dirname, 'assets/metadata-idp.xml')
            ),
        });
    });

    describe('Request', () => {
        it('should create a request login with HTTP-POST', function() {
            const data = SPID.loginRequest('spid-test', 'post');

            expect(data).to.exist;
            expect(data.id).to.exist;
            expect(data.context).to.exist;
            expect(data.relayState).to.exist;
            expect(data.type).to.exist;
        });
        it('should create a request login with HTTP-Redirect', function() {
            const data = SPID.loginRequest('spid-test', 'redirect');

            expect(data).to.exist;
            expect(data.id).to.exist;
            expect(data.context).to.exist;
            expect(data.context).to.have.string(
                'https://idp.spid.gov.it:9443/samlsso?'
            );
        });

        it('should reject a request login with HTTP-SOAP', function() {
            expect(() => SPID.loginRequest('spid-test', 'soap')).to.throw(
                'The binding is not support'
            );
        });

        it('should reject a request with an unknown provider', function() {
            expect(() => SPID.loginRequest('random-spid', 'soap')).to.throw(
                'Missing Identity Provider with key: random-spid'
            );
        });
    });

    describe('Response', () => {
        it('should parse login response', function() {
            const req = createResponse(SAMLResponseBody);

            return SPID.parseResponse(req, 'spid-test', 'post');
        });

        it('should throw for a non-valid login response', function() {
            const req = createResponse({
                SAMLResponse: 'Robba',
                RealyState: 54,
            });

            return SPID.parseResponse(req, 'spid-test', 'post').then(
                () => {
                    throw new Error('It should not passthrough!');
                },
                error => {
                    expect(error).to.be.eql(
                        'this is not a valid saml response with errors'
                    );
                }
            );
        });

        it('should throw for a non-registered Identity Provider login response', function() {
            const req = createResponse({
                SAMLResponse: 'Robba',
                RealyState: 54,
            });

            return SPID.parseResponse(req, 'unknown-spid', 'post').then(
                () => {
                    throw new Error('It should not passthrough!');
                },
                error => {
                    expect(error).to.be.eql(
                        'Missing Identity Provider with key: unknown-spid'
                    );
                }
            );
        });

        it('should throw for a non-valid method for login response', function() {
            const req = createResponse({
                SAMLResponse: 'Robba',
                RealyState: 54,
            });

            return SPID.parseResponse(req, 'spid-test', 'soap').then(
                () => {
                    throw new Error('It should not passthrough!');
                },
                error => {
                    expect(error).to.be.an('error');
                }
            );
        });
    });
});
