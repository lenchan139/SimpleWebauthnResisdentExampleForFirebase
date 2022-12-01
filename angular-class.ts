import { Injectable } from '@angular/core';
import { AngularFireFunctions } from '@angular/fire/compat/functions';
import { lastValueFrom } from 'rxjs';
import { keyOfFunctions } from './consts/keyOfFunctions';

import {
  browserSupportsWebAuthn,
  startRegistration,
  startAuthentication,
} from '@simplewebauthn/browser';
@Injectable({
  providedIn: 'root'
})
export class Fido2WebauthnServiceService {

  constructor(
    private afFunctions: AngularFireFunctions,
  ) { }


  async fido2register() {

    const resp = await lastValueFrom(this.afFunctions.httpsCallable(keyOfFunctions.fido2c_generate_get_registration_options)({}))


    let attResp;
    try {
      const opts = resp

      // Require a resident key for this demo
      opts.authenticatorSelection.residentKey = 'required';
      opts.authenticatorSelection.requireResidentKey = true;
      opts.extensions = {
        credProps: true,
      };

      console.log('Registration Options', JSON.stringify(opts, null, 2));

      // hideAuthForm();

      attResp = await startRegistration(opts);
      console.log('Registration Response', JSON.stringify(attResp, null, 2));
    } catch (error) {
      if (error.name === 'InvalidStateError') {
        return {
          success: false,
          error_code: 'already_registered_with_this_account'
        }
      } else {
        return {
          success: false,
          error_code: error.toString()
        }
      }

    }
    this.afFunctions.httpsCallable(keyOfFunctions.fido2c_verify_registration)(attResp)
      .subscribe(async verificationResp => {

        console.log('verificationResp', verificationResp)
        const verificationJSON = await verificationResp
        console.log('Server Response', JSON.stringify(verificationJSON, null, 2));

        if (verificationJSON && verificationJSON.verified) {

          return {
            success: true,
          }
        } else {

          return { success: false, error_code: 'internal_error', error_body: verificationJSON }
        }
      })

  

}

  async fido2login() {


  let fido2loginMessages = ''
  const opts = await lastValueFrom(this.afFunctions.httpsCallable(keyOfFunctions.fido2c_generate_authentication_options)({}))


  let asseResp;
  try {
    console.log('Authentication Options', JSON.stringify(opts, null, 2));

    // hideAuthForm();

    asseResp = await startAuthentication(opts);

    console.log('Authentication Response', JSON.stringify(asseResp, null, 2));
  } catch (error) {
    fido2loginMessages = error;
    // throw new Error(error);
    return {
      success:false,
      error_code:error.toString()
    }
  }
const r = {...asseResp, expectChallenge:opts.challenge}
  const verificationResp = await lastValueFrom(this.afFunctions.httpsCallable(keyOfFunctions.fido2c_verify_authentication)({
    ...r
  })
  )

  const verificationJSON: {
    verified: boolean,
    multiLoginToken: string,
  } = await verificationResp

  console.log('Server Response', JSON.stringify(verificationJSON, null, 2));

  if (verificationJSON && verificationJSON.verified && verificationJSON.multiLoginToken) {
    return {
      success: true,
      multiLoginToken:verificationJSON.multiLoginToken
    }
    // this.router.navigate(['multiLogin', verificationJSON.multiLoginToken])
  } else {
    return {
      success: false,
      error_code: 'common_erro',
      error_body: verificationJSON,
    }
  }



}
}
