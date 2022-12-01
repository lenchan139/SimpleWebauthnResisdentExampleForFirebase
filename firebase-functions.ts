

import {
    // Registration
    generateRegistrationOptions,
    verifyRegistrationResponse,
    // Authentication
    generateAuthenticationOptions,
} from '@simplewebauthn/server';
import {
    GenerateRegistrationOptionsOpts,
    GenerateAuthenticationOptionsOpts,
    VerifyRegistrationResponseOpts,
    VerifiedRegistrationResponse,
    VerifiedAuthenticationResponse,
    VerifyAuthenticationResponseOpts,
    verifyAuthenticationResponse,


} from '@simplewebauthn/server';
import { admin, dbKeys, functions } from '../commonImportObjects';
import { LoggedInFIDOUser } from './fido2login_conformance';
import { AuthenticatorDevice, RegistrationCredentialJSON, AuthenticationCredentialJSON, } from '@simplewebauthn/typescript-types';
import base64url from 'base64url'
const expectedOrigin = functions.config().fido2?.expected_origin
const expectedDomain = functions.config().fido2?.expected_domain
const rpID = expectedDomain
/**
 * Registration (a.k.a. "Registration")
 */
export const func_fido2c_generate_get_registration_options = functions.https.onCall(async (data, ctx) => {
    const uid = ctx.auth?.uid
    if (!uid) {
        return null;
    }
    const ref_fido2_userinfo = admin.firestore().collection(dbKeys.fido2userInfo).doc(uid)
    // const user = await admin.auth().getUser(uid)
    const snap_fido2_userinfo = await ref_fido2_userinfo.get()
    let fido2userinfo: LoggedInFIDOUser = {
        id: '',
        username: '',
        devices: [],
        currentChallenge: ''

    }

    if (snap_fido2_userinfo?.exists) {
        fido2userinfo = <LoggedInFIDOUser>snap_fido2_userinfo.data()
    }
    if(!fido2userinfo.devices) fido2userinfo.devices = []
    const opts: GenerateRegistrationOptionsOpts = {
        rpName: 'SimpleWebAuthn Example',
        rpID,
        userID: uid,
        userName: ctx.auth.token?.phone_number || ctx.auth?.token.email,
        timeout: 60000,
        attestationType: 'none',
        /**
         * Passing in a user's list of already-registered authenticator IDs here prevents users from
         * registering the same device multiple times. The authenticator will simply throw an error in
         * the browser if it's asked to perform registration when one of these ID's already resides
         * on it.
         */
        excludeCredentials: fido2userinfo.devices.map(dev => ({
            id: dev.credentialID,
            type: 'public-key',
            transports: dev.transports,
        })),
        /**
         * The optional authenticatorSelection property allows for specifying more constraints around
         * the types of authenticators that users to can use for registration
         */
        authenticatorSelection: {
            userVerification: 'required',
            residentKey: 'required',
        },
        /**
         * Support the two most common algorithms: ES256, and RS256
         */
        supportedAlgorithmIDs: [-7, -257],
    };

    const options = generateRegistrationOptions(opts);

    /**
     * The server needs to temporarily remember this value for verification, so don't lose it until
     * after you verify an authenticator response.
     */
    fido2userinfo.currentChallenge = options.challenge;

    await ref_fido2_userinfo.set(fido2userinfo, { merge: true })
    return options;
});

export const func_fido2c_verify_registration = functions.https.onCall(async (data, ctx) => {
    const body: RegistrationCredentialJSON = data;
    const uid = ctx.auth?.uid
    if (!uid) {
        return null;
    }
    const ref_fido2_userinfo = admin.firestore().collection(dbKeys.fido2userInfo).doc(uid)
    // const user = await admin.auth().getUser(uid)
    const snap_fido2_userinfo = await ref_fido2_userinfo.get()
    let fido2userinfo: LoggedInFIDOUser = {
        id: '',
        username: '',
        devices: [],
        currentChallenge: ''

    }

    if (snap_fido2_userinfo?.exists) {
        fido2userinfo = <LoggedInFIDOUser>snap_fido2_userinfo.data()
    }


    let verification: VerifiedRegistrationResponse;
    try {
        const opts: VerifyRegistrationResponseOpts = {
            credential: body,
            expectedChallenge: `${fido2userinfo.currentChallenge}`,
            expectedOrigin,
            expectedRPID: rpID,
            requireUserVerification: true,
        };
        verification = await verifyRegistrationResponse(opts);
    } catch (error) {
        const _error = error as Error;
        console.error(_error);
        return { error: _error.message };
    }

    const { verified, registrationInfo } = verification;

    if (verified && registrationInfo) {
        const { credentialPublicKey, credentialID, counter } = registrationInfo;

        const existingDevice = fido2userinfo.devices.find(device => device.credentialID.equals(credentialID));

        if (!existingDevice) {
            /**
             * Add the returned device to the user's list of devices
             */
            const newDevice: AuthenticatorDevice = {
                credentialPublicKey,
                credentialID,
                counter,
                transports: body.transports,
            };
            fido2userinfo.devices.push(newDevice);
        }
    }

    await ref_fido2_userinfo.set(fido2userinfo, {
        merge: true
    });

    return { verified };
});

/**
 * Login (a.k.a. "Authentication")
 */
export const func_fido2c_generate_authentication_options = functions.https.onCall(async (data, ctx) => {
    // You need to know the user by this point
    // const user = inMemoryUserDeviceDB[loggedInUserId];

    const opts: GenerateAuthenticationOptionsOpts = {
        timeout: 60000,
        // allowCredentials: user.devices.map(dev => ({
        //     id: dev.credentialID,
        //     type: 'public-key',
        //     transports: dev.transports,
        // })),
        userVerification: 'required',
        rpID,
    };

    const options = generateAuthenticationOptions(opts);

    /**
     * The server needs to temporarily remember this value for verification, so don't lose it until
     * after you verify an authenticator response.
     */
    // inMemoryUserDeviceDB[loggedInUserId].currentChallenge = options.challenge;

    return (options);
});

export const func_fido2c_verify_authentication = functions.https.onCall(async (data, ctx) => {
    const body: AuthenticationCredentialJSON = data;
    const uid = body.response?.userHandle

    const expectedChallenge = body.expectChallenge;

    if (!uid) {
        return null;
    }
    const ref_fido2_userinfo = admin.firestore().collection(dbKeys.fido2userInfo).doc(uid)
    // const user = await admin.auth().getUser(uid)
    const snap_fido2_userinfo = await ref_fido2_userinfo.get()
    let fido2userinfo: LoggedInFIDOUser = {
        id: '',
        username: '',
        devices: [],
        currentChallenge: ''

    }

    if (snap_fido2_userinfo?.exists) {
        fido2userinfo = <LoggedInFIDOUser>snap_fido2_userinfo.data()
    }

    let dbAuthenticator;
    const bodyCredIDBuffer = base64url.toBuffer(body.rawId);
    // "Query the DB" here for an authenticator matching `credentialID`
    for (const dev of fido2userinfo.devices) {
        if (dev.credentialID.equals(bodyCredIDBuffer)) {
            dbAuthenticator = dev;
            break;
        }
    }

    if (!dbAuthenticator) {
        return { error: 'Authenticator is not registered with this site' };
    }

    let verification: VerifiedAuthenticationResponse;
    try {
        const opts: VerifyAuthenticationResponseOpts = {
            credential: body,
            expectedChallenge: `${expectedChallenge}`,
            expectedOrigin,
            expectedRPID: rpID,
            authenticator: dbAuthenticator,
            requireUserVerification: true,
        };
        verification = await verifyAuthenticationResponse(opts);
    } catch (error) {
        const _error = error as Error;
        console.error(_error);
        return { error: _error.message };
    }

    const { verified, authenticationInfo } = verification;
    let multiLoginToken = ''
    if (verified) {
        // Update the authenticator's counter in the DB to the newest count in the authentication
        dbAuthenticator.counter = authenticationInfo.newCounter;

        const token = await admin.auth().createCustomToken(uid)
        const tokenDoc = await admin.firestore().collection(dbKeys.multi_login_tokens)
            .add({
                token: token,
            })
        multiLoginToken = tokenDoc.id
    }

   return  {
        verified,
        multiLoginToken
    }
});
