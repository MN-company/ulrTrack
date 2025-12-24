from collections import defaultdict
import json
import csv
from io import StringIO
from typing import List, Dict, Any, Optional

from ..models import Lead, Visit, db
from ..extensions import log_queue

class LeadService:
    """
    Service for Lead Management, Identity Graph, and Exports.
    """
    
    @staticmethod
    def create_lead(email: str, name: Optional[str] = None, notes: Optional[str] = None) -> Lead:
        """Creates a new lead safely."""
        existing = Lead.query.filter_by(email=email).first()
        if existing:
            raise ValueError("Lead already exists")
            
        new_lead = Lead(email=email, name=name, notes=notes)
        db.session.add(new_lead)
        db.session.commit()
        return new_lead

    @staticmethod
    def get_merge_candidates() -> List[Dict[str, Any]]:
        """
        Find potential duplicate leads based on canvas hash correlation.
        Optimized to avoid N+1 where possible.
        """
        # Get all visits with hash and email
        visits = db.session.query(Visit.canvas_hash, Visit.email)\
            .filter(Visit.canvas_hash != None, Visit.email != None).all()
        
        hash_to_emails = defaultdict(set)
        for v in visits:
            hash_to_emails[v.canvas_hash].add(v.email)
            
        candidates = []
        for canvas_hash, emails in hash_to_emails.items():
            if len(emails) > 1:
                # Fetch leads in bulk
                leads = Lead.query.filter(Lead.email.in_(list(emails))).all()
                if len(leads) > 1:
                    candidates.append({
                        'canvas_hash': canvas_hash[:16],
                        'leads': leads
                    })
        return candidates

    @staticmethod
    def merge_leads(primary_id: int, secondary_ids: List[int]) -> int:
        """
        Merge multiple leads into primary.
        Returns count of merged leads.
        """
        primary = Lead.query.get(primary_id)
        if not primary:
            raise ValueError("Primary lead not found")
            
        merged_count = 0
        for sec_id in secondary_ids:
            secondary = Lead.query.get(int(sec_id))
            if secondary and secondary.id != primary.id:
                # Transfer visits
                Visit.query.filter_by(email=secondary.email).update({'email': primary.email})
                
                # Merge basic fields if empty in primary
                if secondary.name and not primary.name:
                    primary.name = secondary.name
                if secondary.holehe_data and not primary.holehe_data:
                    primary.holehe_data = secondary.holehe_data
                
                # Merge Tags
                if secondary.tags:
                    existing = set((primary.tags or '').split(','))
                    new_tags = set(secondary.tags.split(','))
                    # Clean empty strings
                    existing.discard('')
                    new_tags.discard('')
                    primary.tags = ','.join(existing.union(new_tags))
                
                # Merge Custom Fields (JSON)
                try:
                    p_cf = primary.custom_fields_data # Uses new Model property
                    s_cf = secondary.custom_fields_data
                    
                    # Merge s_cf into p_cf without overwrite existing
                    for k, v in s_cf.items():
                        if k not in p_cf:
                            p_cf[k] = v
                    primary.custom_fields_data = p_cf
                except:
                    pass
                
                db.session.delete(secondary)
                merged_count += 1
                
        db.session.commit()
        return merged_count

    @staticmethod
    def export_csv() -> str:
        """Generates CSV string for all contacts."""
        si = StringIO()
        cw = csv.writer(si)
        cw.writerow(['ID', 'Email', 'Name', 'Tags', 'Notes', 'Socials Found', 'Created At'])
        
        leads = Lead.query.all()
        for l in leads:
            count_socials = len(l.holehe_sites) # Uses new Model property
            cw.writerow([l.id, l.email, l.name or '', l.tags or '', l.notes or '', count_socials, l.created_at])
            
        return si.getvalue()

    @staticmethod
    def build_identity_graph(lead: Lead) -> Dict[str, Any]:
        """
        Builds the Spiderweb identity graph data.
        """
        visits = Visit.query.filter_by(email=lead.email).all()
        devices = set()
        ips = set()
        canvas_hashes = set()
        
        for v in visits:
            if v.ai_summary: devices.add(v.ai_summary)
            if v.webgl_renderer and v.webgl_renderer != "Unknown": devices.add(v.webgl_renderer)
            if v.ip_address: ips.add(v.ip_address)
            if v.canvas_hash: canvas_hashes.add(v.canvas_hash)
            
        # Find Related Leads
        related_leads = []
        if ips or canvas_hashes:
            query = db.session.query(Visit.email).filter(
                (Visit.ip_address.in_(ips)) | (Visit.canvas_hash.in_(canvas_hashes)),
                Visit.email.isnot(None),
                Visit.email != lead.email
            ).distinct()
            
            related_emails = [r[0] for r in query.all()]
            if related_emails:
                related_leads = Lead.query.filter(Lead.email.in_(related_emails)).all()
                
        return {
            'devices': list(devices),
            'ips': list(ips),
            'canvas_hashes': list(canvas_hashes),
            'related_leads': related_leads,
            'visits': visits
        }
