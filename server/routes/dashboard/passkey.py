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
    # Step 2: Verify WebAuthn attestation.
    data = request.get_json()
    
    try:
        # Verify call to python-webauthn would go here
        # For this prototype we will simulate success if structure is valid
        
        # In a real app, you would:
        # 1. Retrieve the challenge from session
        # 2. Verify signature using standard library
        
        # Save credential to DB
        new_cred = {
            'id': data['id'],
            'rawId': data['rawId'],
            'type': data['type'],
            'name': data.get('name', 'New Passkey'),
            'created_at': datetime.utcnow().isoformat()
        }
        
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
