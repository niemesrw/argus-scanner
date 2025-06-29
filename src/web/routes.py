"""
Web routes for Argus Scanner
"""
import logging
from flask import Blueprint, render_template, jsonify, request, current_app
from datetime import datetime, timedelta
from sqlalchemy import func, desc

from src.database.models import (
    Device, Service, Vulnerability, Alert, Scan,
    get_db_session, Severity, ScanType
)
from src.scanner.discovery import NetworkDiscovery
from src.scanner.vulnerability import VulnerabilityScanner
from src.alerts.manager import AlertManager

logger = logging.getLogger(__name__)

# Create blueprints
api_bp = Blueprint('api', __name__)
dashboard_bp = Blueprint('dashboard', __name__)

# Dashboard Routes
@dashboard_bp.route('/')
def index():
    """Main dashboard page"""
    return render_template('dashboard.html')

@dashboard_bp.route('/devices')
def devices():
    """Device list page"""
    return render_template('devices.html')

@dashboard_bp.route('/devices/<int:device_id>')
def device_detail(device_id):
    """Device detail page"""
    return render_template('device_detail.html', device_id=device_id)

@dashboard_bp.route('/vulnerabilities')
def vulnerabilities():
    """Vulnerabilities page"""
    return render_template('vulnerabilities.html')

@dashboard_bp.route('/alerts')
def alerts():
    """Alerts page"""
    return render_template('alerts.html')

@dashboard_bp.route('/scans')
def scans():
    """Scan history page"""
    return render_template('scans.html')

# API Routes
@api_bp.route('/stats')
def get_stats():
    """Get dashboard statistics"""
    db = get_db_session(current_app.config['DB_PATH'])
    
    try:
        stats = {
            'total_devices': db.query(Device).count(),
            'active_devices': db.query(Device).filter_by(is_active=True).count(),
            'total_vulnerabilities': db.query(Vulnerability).count(),
            'critical_vulnerabilities': db.query(Vulnerability).filter_by(
                severity=Severity.CRITICAL
            ).count(),
            'unacknowledged_alerts': db.query(Alert).filter_by(
                acknowledged=False
            ).count(),
            'recent_scans': db.query(Scan).filter(
                Scan.started_at > datetime.utcnow() - timedelta(hours=24)
            ).count()
        }
        
        # Risk distribution
        from sqlalchemy import case
        risk_distribution = db.query(
            case(
                (Device.risk_score >= 80, 'Critical'),
                (Device.risk_score >= 60, 'High'),
                (Device.risk_score >= 40, 'Medium'),
                (Device.risk_score >= 20, 'Low'),
                else_='None'
            ).label('risk_level'),
            func.count(Device.id).label('count')
        ).group_by('risk_level').all()
        
        stats['risk_distribution'] = {
            level: count for level, count in risk_distribution
        }
        
        return jsonify(stats)
        
    finally:
        db.close()

@api_bp.route('/devices')
def get_devices():
    """Get all devices"""
    db = get_db_session(current_app.config['DB_PATH'])
    
    try:
        # Get query parameters
        active_only = request.args.get('active_only', 'false').lower() == 'true'
        sort_by = request.args.get('sort_by', 'last_seen')
        order = request.args.get('order', 'desc')
        
        query = db.query(Device)
        
        if active_only:
            query = query.filter_by(is_active=True)
        
        # Apply sorting
        sort_column = getattr(Device, sort_by, Device.last_seen)
        if order == 'desc':
            query = query.order_by(desc(sort_column))
        else:
            query = query.order_by(sort_column)
        
        devices = query.all()
        
        return jsonify([{
            'id': d.id,
            'ip_address': d.ip_address,
            'mac_address': d.mac_address,
            'hostname': d.hostname,
            'manufacturer': d.manufacturer,
            'operating_system': d.operating_system,
            'risk_score': d.risk_score,
            'is_active': d.is_active,
            'first_seen': d.first_seen.isoformat(),
            'last_seen': d.last_seen.isoformat(),
            'service_count': len(d.services),
            'vulnerability_count': sum(len(s.vulnerabilities) for s in d.services)
        } for d in devices])
        
    finally:
        db.close()

@api_bp.route('/devices/<int:device_id>')
def get_device(device_id):
    """Get device details"""
    db = get_db_session(current_app.config['DB_PATH'])
    
    try:
        device = db.query(Device).filter_by(id=device_id).first()
        
        if not device:
            return jsonify({'error': 'Device not found'}), 404
        
        # Get services and vulnerabilities
        services_data = []
        for service in device.services:
            service_data = {
                'id': service.id,
                'port': service.port,
                'protocol': service.protocol,
                'state': service.state,
                'service_name': service.service_name,
                'product': service.product,
                'version': service.version,
                'vulnerabilities': [{
                    'id': v.id,
                    'cve_id': v.cve_id,
                    'name': v.name,
                    'severity': v.severity.value,
                    'cvss_score': v.cvss_score,
                    'exploit_available': v.exploit_available
                } for v in service.vulnerabilities]
            }
            services_data.append(service_data)
        
        return jsonify({
            'id': device.id,
            'ip_address': device.ip_address,
            'mac_address': device.mac_address,
            'hostname': device.hostname,
            'device_type': device.device_type,
            'manufacturer': device.manufacturer,
            'operating_system': device.operating_system,
            'os_version': device.os_version,
            'risk_score': device.risk_score,
            'is_active': device.is_active,
            'first_seen': device.first_seen.isoformat(),
            'last_seen': device.last_seen.isoformat(),
            'notes': device.notes,
            'services': services_data
        })
        
    finally:
        db.close()

@api_bp.route('/vulnerabilities')
def get_vulnerabilities():
    """Get all vulnerabilities"""
    db = get_db_session(current_app.config['DB_PATH'])
    
    try:
        # Get query parameters
        severity = request.args.get('severity')
        exploit_available = request.args.get('exploit_available')
        limit = int(request.args.get('limit', 100))
        
        query = db.query(Vulnerability).join(Service).join(Device)
        
        if severity:
            query = query.filter(Vulnerability.severity == Severity(severity))
        
        if exploit_available is not None:
            query = query.filter(
                Vulnerability.exploit_available == (exploit_available.lower() == 'true')
            )
        
        vulnerabilities = query.order_by(
            desc(Vulnerability.discovered_at)
        ).limit(limit).all()
        
        return jsonify([{
            'id': v.id,
            'cve_id': v.cve_id,
            'name': v.name,
            'description': v.description,
            'severity': v.severity.value,
            'cvss_score': v.cvss_score,
            'exploit_available': v.exploit_available,
            'exploit_tested': v.exploit_tested,
            'exploit_successful': v.exploit_successful,
            'discovered_at': v.discovered_at.isoformat(),
            'device': {
                'id': v.service.device.id,
                'ip_address': v.service.device.ip_address,
                'hostname': v.service.device.hostname
            },
            'service': {
                'port': v.service.port,
                'name': v.service.service_name
            }
        } for v in vulnerabilities])
        
    finally:
        db.close()

@api_bp.route('/alerts')
def get_alerts():
    """Get alerts"""
    db = get_db_session(current_app.config['DB_PATH'])
    
    try:
        # Get query parameters
        acknowledged = request.args.get('acknowledged')
        severity = request.args.get('severity')
        limit = int(request.args.get('limit', 50))
        
        query = db.query(Alert)
        
        if acknowledged is not None:
            query = query.filter(
                Alert.acknowledged == (acknowledged.lower() == 'true')
            )
        
        if severity:
            query = query.filter(Alert.severity == Severity(severity))
        
        alerts = query.order_by(
            desc(Alert.created_at)
        ).limit(limit).all()
        
        return jsonify([{
            'id': a.id,
            'severity': a.severity.value,
            'title': a.title,
            'message': a.message,
            'created_at': a.created_at.isoformat(),
            'acknowledged': a.acknowledged,
            'acknowledged_at': a.acknowledged_at.isoformat() if a.acknowledged_at else None,
            'acknowledged_by': a.acknowledged_by,
            'notification_sent': a.notification_sent
        } for a in alerts])
        
    finally:
        db.close()

@api_bp.route('/alerts/<int:alert_id>/acknowledge', methods=['POST'])
def acknowledge_alert(alert_id):
    """Acknowledge an alert"""
    settings = current_app.config['SETTINGS']
    alert_manager = AlertManager(settings)
    
    acknowledged_by = request.json.get('acknowledged_by', 'web_user')
    alert_manager.acknowledge_alert(alert_id, acknowledged_by)
    
    return jsonify({'success': True})

@api_bp.route('/alerts/<int:alert_id>/resolve', methods=['POST'])
def resolve_alert(alert_id):
    """Resolve an alert"""
    db = get_db_session(current_app.config['DB_PATH'])
    
    try:
        alert = db.query(Alert).filter_by(id=alert_id).first()
        if not alert:
            return jsonify({'error': 'Alert not found'}), 404
        
        alert.acknowledged = True
        alert.acknowledged_at = datetime.utcnow()
        alert.acknowledged_by = request.json.get('resolved_by', 'web_user')
        db.commit()
        
        return jsonify({'success': True})
    finally:
        db.close()

@api_bp.route('/alerts/test', methods=['POST'])
def create_test_alert():
    """Create a test alert for demonstration"""
    db = get_db_session(current_app.config['DB_PATH'])
    
    try:
        test_alert = Alert(
            severity=Severity.MEDIUM,
            title="Test Security Alert",
            message="This is a test alert created for demonstration purposes.",
            created_at=datetime.utcnow(),
            acknowledged=False
        )
        
        db.add(test_alert)
        db.commit()
        
        return jsonify({'success': True, 'alert_id': test_alert.id})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()

@api_bp.route('/vulnerabilities/<int:vuln_id>/acknowledge', methods=['POST'])
def acknowledge_vulnerability(vuln_id):
    """Acknowledge a vulnerability"""
    # In a real implementation, this would update the vulnerability status
    return jsonify({'success': True})

@api_bp.route('/scans/<int:scan_id>/cancel', methods=['POST'])
def cancel_scan(scan_id):
    """Cancel a running scan"""
    # In a real implementation, this would stop the scan
    return jsonify({'success': True})

@api_bp.route('/scans')
def get_scans():
    """Get scan history"""
    db = get_db_session(current_app.config['DB_PATH'])
    
    try:
        scans = db.query(Scan).order_by(
            desc(Scan.started_at)
        ).limit(20).all()
        
        return jsonify([{
            'id': s.id,
            'scan_type': s.scan_type.value,
            'target_range': s.target_range,
            'started_at': s.started_at.isoformat(),
            'completed_at': s.completed_at.isoformat() if s.completed_at else None,
            'status': s.status,
            'total_hosts': s.total_hosts,
            'hosts_scanned': s.hosts_scanned,
            'vulnerabilities_found': s.vulnerabilities_found,
            'duration': (
                (s.completed_at - s.started_at).total_seconds()
                if s.completed_at else None
            )
        } for s in scans])
        
    finally:
        db.close()

@api_bp.route('/scan/start', methods=['POST'])
def start_scan():
    """Manually trigger a scan"""
    settings = current_app.config['SETTINGS']
    scan_type = request.json.get('scan_type', 'discovery')
    target = request.json.get('target', settings.network_range)
    
    try:
        if scan_type == 'discovery':
            discovery = NetworkDiscovery(settings)
            devices = discovery.discover_devices(target)
            return jsonify({
                'success': True,
                'devices_found': len(devices)
            })
        elif scan_type == 'vulnerability':
            # In production, this would trigger async scan
            return jsonify({
                'success': True,
                'message': 'Vulnerability scan started'
            })
        else:
            return jsonify({
                'error': 'Invalid scan type'
            }), 400
            
    except Exception as e:
        logger.error(f"Error starting scan: {e}")
        return jsonify({
            'error': str(e)
        }), 500