"""
WebAuthn/Passkey Implementation
Complete passkey registration and authentication using py_webauthn library.
"""
from flask import Blueprint, request, jsonify, session, redirect, url_for, flash
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
from datetime import datetime

from ...models import User, db
from ...config import Config

bp = Blueprint('dashboard_passkey', __name__)

# WebAuthn Configuration
RP_ID = Config.SERVER_URL.replace('https://', '').replace('http://', '').split(':')[0].split('/')[0]
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
                PublicKeyCredentialDescriptor(id=base64.urlsafe_b64decode(c['id'] + '=='))
                for c in creds
            ]
        except Exception:
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
            resident_key=ResidentKeyRequirement.PREFERRED,
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
    data = request.get_json()
    
    try:
        challenge = base64.b64decode(session.get('webauthn_challenge', ''))
        credential_data = data.get('credential', data)
        device_name = data.get('name', 'New Passkey')
        
        # Verify registration response
        verification = verify_registration_response(
            credential=credential_data,
            expected_challenge=challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
        )
        
        # Save credential to DB
        user = User.query.get(current_user.id)
        creds = json.loads(user.passkey_credentials or '[]')
        
        new_cred = {
            'id': base64.urlsafe_b64encode(verification.credential_id).decode().rstrip('='),
            'public_key': base64.urlsafe_b64encode(verification.credential_public_key).decode(),
            'sign_count': verification.sign_count,
            'name': device_name,
            'created_at': datetime.utcnow().isoformat()
        }
        
        creds.append(new_cred)
        user.passkey_credentials = json.dumps(creds)
        db.session.commit()
        
        # Clear session
        session.pop('webauthn_challenge', None)
        
        return jsonify({'status': 'success', 'message': 'Passkey registered successfully'})
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@bp.route('/passkey/auth/options', methods=['POST'])
def passkey_auth_options():
    """Generate authentication options for passkey login."""
    data = request.get_json() or {}
    username = data.get('username')
    
    if not username:
        return jsonify({'error': 'Username required'}), 400
    
    user = User.query.filter_by(username=username).first()
    if not user or not user.passkey_credentials:
        return jsonify({'error': 'No passkeys registered'}), 404
    
    try:
        creds = json.loads(user.passkey_credentials)
        allow_credentials = [
            PublicKeyCredentialDescriptor(id=base64.urlsafe_b64decode(c['id'] + '=='))
            for c in creds
        ]
    except Exception:
        return jsonify({'error': 'Invalid credential data'}), 500
    
    options = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    
    # Store challenge and user_id in session
    session['webauthn_challenge'] = base64.b64encode(options.challenge).decode()
    session['webauthn_user_id'] = user.id
    
    return jsonify(json.loads(options_to_json(options)))

@bp.route('/passkey/auth/verify', methods=['POST'])
def passkey_auth_verify():
    """Verify passkey authentication response."""
    data = request.get_json()
    
    try:
        challenge = base64.b64decode(session.get('webauthn_challenge', ''))
        user_id = session.get('webauthn_user_id')
        
        if not user_id:
            return jsonify({'verified': False, 'error': 'Session expired'}), 400
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({'verified': False, 'error': 'User not found'}), 404
        
        creds = json.loads(user.passkey_credentials or '[]')
        
        # Find matching credential
        credential_id = data.get('id') or data.get('rawId')
        matching_cred = next((c for c in creds if c['id'] == credential_id), None)
        
        if not matching_cred:
            return jsonify({'verified': False, 'error': 'Credential not found'}), 404
        
        # Verify authentication
        verification = verify_authentication_response(
            credential=data,
            expected_challenge=challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            credential_public_key=base64.urlsafe_b64decode(matching_cred['public_key'] + '=='),
            credential_current_sign_count=matching_cred.get('sign_count', 0),
        )
        
        # Update sign count
        matching_cred['sign_count'] = verification.new_sign_count
        user.passkey_credentials = json.dumps(creds)
        db.session.commit()
        
        # Login user
        login_user(user, remember=True)
        
        # Clear session
        session.pop('webauthn_challenge', None)
        session.pop('webauthn_user_id', None)
        
        return jsonify({
            'verified': True,
            'redirect': url_for('dashboard.dashboard_links.dashboard_home')
        })
        
    except Exception as e:
        return jsonify({'verified': False, 'error': str(e)}), 400

@bp.route('/passkey/list')
@login_required
def passkey_list():
    """List user's registered passkeys."""
    user = User.query.get(current_user.id)
    
    passkeys = []
    if user.passkey_credentials:
        try:
            passkeys = json.loads(user.passkey_credentials)
        except Exception:
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
    except Exception as e:
        return jsonify({'success': False, 'error': f'Failed to delete: {str(e)}'}), 500
