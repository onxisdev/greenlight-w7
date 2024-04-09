import { session, dialog } from 'electron'
import { createWindow } from './helpers'
import Application from './application'
import { Xal } from 'xal-node'
import AuthTokenStore from './helpers/tokenstore'


export default class Authentication {
    _application:Application

    _tokenStore:AuthTokenStore
    _xal:Xal
    
    _authWindow
    _authCallback

    _isAuthenticating:boolean = false
    _isAuthenticated:boolean = false
    _appLevel:number = 0

    constructor(application:Application){
        this._application = application
        this._tokenStore = new AuthTokenStore()
        this._tokenStore.load()
        this._xal = new Xal(this._tokenStore)
    }

    checkAuthentication(){
        this._application.log('authenticationV2', __filename+'[checkAuthentication()] Starting token check...')
        if(this._tokenStore.hasValidAuthTokens()){
            this._application.log('authenticationV2', __filename+'[checkAuthentication()] Tokens are valid.')
            this.startSilentFlow()

            return true

        } else {
            if(this._tokenStore.getUserToken() !== undefined){
                // We have a user token, lets try to refresh it.
                this._application.log('authenticationV2', __filename+'[checkAuthentication()] Tokens are expired but we have a user token. Lets try to refresh the tokens.')
                this.startSilentFlow()

                return true
    
            } else {
                this._application.log('authenticationV2', __filename+'[checkAuthentication()] No tokens are present.')
                return false
            }
        }
    }

    startSilentFlow(){
        this._application.log('authenticationV2', __filename+'[startSilentFlow()] Starting silent flow...')
        this._isAuthenticating = true

        this._xal.refreshTokens(this._tokenStore).then((result) => {
            this._application.log('authenticationV2', __filename+'[startSilentFlow()] Refreshed tokens:', result)

            this._application.authenticationCompleted()
            this._isAuthenticating = false
            this._isAuthenticated = true
            this._appLevel = 2

        }).catch((err) => {
            this._application.log('authenticationV2', __filename+'[startSilentFlow()] Error refreshing tokens:', err)
            this._tokenStore.clear()
        })
    }

    startAuthflow(){
        this._application.log('authenticationV2', __filename+'[startAuthflow()] Starting authentication flow')
        
        this._xal.getRedirectUri().then((redirect) => {
            this.openAuthWindow(redirect.sisuAuth.MsaOauthRedirect)

            this._authCallback = (redirectUri) => {
                this._application.log('authenticationV2', __filename+'[startAuthFlow()] Got redirect URI:', redirectUri)
                this._xal.authenticateUser(this._tokenStore, redirect, redirectUri).then((result) => {
                    this._application.log('authenticationV2', __filename+'[startAuthFlow()] Authenticated user:', result)

                    this.startSilentFlow()

                }).catch((err) => {
                    this._application.log('authenticationV2', __filename+'[startAuthFlow()] Error authenticating user:', err)
                    dialog.showErrorBox('Error', 'Error authenticating user. Error details: '+JSON.stringify(err))
                })
            }
        }).catch((err) => {
            this._application.log('authenticationV2', __filename+'[startAuthFlow()] Error getting redirect URI:', err)
            dialog.showErrorBox('Error', 'Error getting redirect URI. Error details: '+JSON.stringify(err))
        })
    }

    startWebviewHooks(){
        this._application.log('authenticationV2', __filename+'[startWebviewHooks()] Starting webview hooks')

        session.defaultSession.webRequest.onHeadersReceived({
            urls: [
                'https://login.live.com/oauth20_authorize.srf?*',
                'https://login.live.com/ppsecure/post.srf?*',
            ],
        }, (details, callback) => {

            if(details.responseHeaders.Location !== undefined && details.responseHeaders.Location[0].includes(this._xal._app.RedirectUri)){
                this._application.log('authenticationV2', __filename+'[startWebviewHooks()] Got redirect URI from OAUTH:', details.responseHeaders.Location[0])
                this._authWindow.close()

                if(this._authCallback !== undefined){
                    this._authCallback(details.responseHeaders.Location[0])
                } else {
                    this._application.log('authenticationV2', __filename+'[startWebviewHooks()] Authentication Callback is not defined:', this._authCallback)
                    dialog.showErrorBox('Error', 'Authentication Callback is not defined. Error details: '+JSON.stringify(this._authCallback))
                }

                callback({ cancel: true })
            } else {
                callback(details)
            }
        })
    }

    openAuthWindow(url){
        const authWindow = createWindow('auth', {
            width: 500,
            height: 600,
            title: 'Authentication',
        })
        
        authWindow.loadURL(url)
        this._authWindow = authWindow

        this._authWindow.on('close', () => {
            this._application.log('authenticationV2', __filename+'[openAuthWindow()] Closed auth window')
            // @TODO: What to do?
        })
    }

    
}
