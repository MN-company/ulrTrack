"""
WebAuthn/Passkey Implementation
Complete passkey registration and authentication using py_webauthn library.
"""
from flask import Blueprint, request, jsonify, session, render_template, redirect, url_for, flash
from flask_login import login_required, current_user, login_user
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
)
from webauthn.helpers.structs import (
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
import json
import base64

from ...models import User, db
from ...config import Config

bp = Blueprint('dashboard_passkey', __name__)

# WebAuthn Configuration
RP_ID = Config.SERVER_URL.replace('https://', '').replace('http://', '').split(':')[0]
RP_NAME = "ULRTrack Dashboard"
ORIGIN = Config.SERVER_URL

@bp.route('/passkey/register/options', methods=['POST'])
@login_required
def passkey_register_options():
    """Generate registration options for new passkey."""
    user = User.query.get(current_user.id)
    
    # Parse existing credentials
    existing_credentials = []
    if user.passkey_credentials:
        try:
            creds = json.loads(user.passkey_credentials)
            existing_credentials = [
                PublicKeyCredentialDescriptor(id=base64.b64decode(c['id']))
                for c in creds
            ]
        except:
            pass
    
    # Generate registration options
    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=str(user.id).encode(),
        user_name=user.username,
        user_display_name=user.username,
        exclude_credentials=existing_credentials,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
        supported_pub_key_algs=[
            COSEAlgorithmIdentifier.ECDSA_SHA_256,
            COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
        ],
    )
    
    # Store challenge in session
    session['webauthn_challenge'] = base64.b64encode(options.challenge).decode()
    
    return jsonify(json.loads(options_to_json(options)))

@bp.route('/passkey/register/verify', methods=['POST'])
@login_required
def passkey_register_verify():
    """Verify passkey registration response."""
    user = User.query.get(current_user.id)
    
    try:
        # Get challenge from session
        challenge = base64.b64decode(session.get('webauthn_challenge', ''))
        
        # Get response from client
        credential = request.get_json()
        
        # Verify registration
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
        )
        
        # Store credential
        new_credential = {
            'id': base64.b64encode(verification.credential_id).decode(),
            'public_key': base64.b64encode(verification.credential_public_key).decode(),
            'sign_count': verification.sign_count,
            'name': request.json.get('name', 'My Passkey'),
            'created_at': str(datetime.utcnow()),
        }
        
        # Add to user's credentials
        credentials = []
        if user.passkey_credentials:
            try:
                credentials = json.loads(user.passkey_credentials)
            except:
                credentials = []
        
        credentials.append(new_credential)
        user.passkey_credentials = json.dumps(credentials)
        db.session.commit()
        
        # Clear session
        session.pop('webauthn_challenge', None)
        
        return jsonify({
            'verified': True,
            'message': 'Passkey registered successfully!'
        })
        
    except Exception as e:
        return jsonify({
            'verified': False,
            'error': str(e)
        }), 400

@bp.route('/passkey/auth/options', methods=['POST'])
def passkey_auth_options():
    """Generate authentication options for passkey login."""
    username = request.json.get('username')
    
    if not username:
        return jsonify({'error': 'Username required'}), 400
    
    user = User.query.filter_by(username=username).first()
    if not user or not user.passkey_credentials:
        return jsonify({'error': 'No passkeys registered'}), 404
    
    # Parse user's credentials
    try:
        creds = json.loads(user.passkey_credentials)
        allow_credentials = [
            PublicKeyCredentialDescriptor(id=base64.b64decode(c['id']))
            for c in creds
        ]
    except:
        return jsonify({'error': 'Invalid credentials'}), 500
    
    # Generate authentication options
    options = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    
    # Store challenge
    session['webauthn_challenge'] = base64.b64encode(options.challenge).decode()
    session['webauthn_user_id'] = user.id
    
    return jsonify(json.loads(options_to_json(options)))

@bp.route('/passkey/auth/verify', methods=['POST'])
def passkey_auth_verify():
    """Verify passkey authentication response."""
    try:
        # Get challenge and user from session
        challenge = base64.b64decode(session.get('webauthn_challenge', ''))
        user_id = session.get('webauthn_user_id')
        
        if not user_id:
            return jsonify({'verified': False, 'error': 'Session expired'}), 400
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({'verified': False, 'error': 'User not found'}), 404
        
        # Get credential response
        credential = request.get_json()
        
        # Find matching credential
        creds = json.loads(user.passkey_credentials)
        credential_id = credential.get('id')
        
        matching_cred = next((c for c in creds if c['id'] == credential_id), None)
        if not matching_cred:
            return jsonify({'verified': False, 'error': 'Credential not found'}), 404
        
        # Verify authentication
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            credential_public_key=base64.b64decode(matching_cred['public_key']),
            credential_current_sign_count=matching_cred['sign_count'],
        )
        
        # Update sign count
        matching_cred['sign_count'] = verification.new_sign_count
        user.passkey_credentials = json.dumps(creds)
        db.session.commit()
        
        # Login user!
        login_user(user, remember=True)
        
        # Clear session
        session.pop('webauthn_challenge', None)
        session.pop('webauthn_user_id', None)
        
        return jsonify({
            'verified': True,
            'redirect': url_for('dashboard.dashboard_links.dashboard_home')
        })
        
    except Exception as e:
        return jsonify({
            'verified': False,
            'error': str(e)
        }), 400

@bp.route('/passkey/list')
@login_required
def passkey_list():
    """List user's registered passkeys."""
    user = User.query.get(current_user.id)
    
    passkeys = []
    if user.passkey_credentials:
        try:
            passkeys = json.loads(user.passkey_credentials)
        except:
            pass
    
    return jsonify(passkeys)

@bp.route('/passkey/delete/<credential_id>', methods=['POST'])
@login_required
def passkey_delete(credential_id):
    """Delete a passkey."""
    user = User.query.get(current_user.id)
    
    try:
        creds = json.loads(user.passkey_credentials or '[]')
        creds = [c for c in creds if c['id'] != credential_id]
        
        user.passkey_credentials = json.dumps(creds)
        db.session.commit()
        
        flash('Passkey deleted successfully', 'success')
        return jsonify({'success': True})
    except:
        return jsonify({'success': False, 'error': 'Failed to delete'}), 500
