/*
Copyright 2015 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import { TrackRec } from './statusStore';
import * as RT from './constants';

const STORE_NAME = 'tlpt_status';

export const makeGetter = reqType => [[STORE_NAME, reqType], rec => {
  return rec || new TrackRec();
}];

export const initAppAttempt = makeGetter(RT.TRYING_TO_INIT_APP);  
export const loginAttempt = makeGetter(RT.TRYING_TO_LOGIN);
export const fetchInviteAttempt = makeGetter(RT.FETCHING_INVITE);
export const signupAttempt = makeGetter(RT.TRYING_TO_SIGN_UP);
export const initSettingsAttempt = makeGetter(RT.TRYING_TO_INIT_SETTINGS);
export const changePasswordAttempt = makeGetter(RT.TRYING_TO_CHANGE_PSW);