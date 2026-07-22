"""
app/reports/routes.py

Displays a paginated, filterable history of the logged-in user's scans,
and provides CSV/PDF export of that same history.
"""

import io
import csv
from flask import render_template, request, send_file
from flask_login import login_required, current_user
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, landscape
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch

from app.reports import reports_bp
from app.models import Scan

SCANS_PER_PAGE = 10
VALID_SCAN_TYPES = ['vulnerability', 'phishing', 'malware']


def get_filtered_scans(selected_type):
    """
    SECURITY NOTE: always filtered by Scan.user_id == current_user.id,
    so a user can only ever export their OWN scan history -- same
    IDOR-prevention principle as the history view.
    """
    query = Scan.query.filter_by(user_id=current_user.id)
    if selected_type in VALID_SCAN_TYPES:
        query = query.filter_by(scan_type=selected_type)
    return query.order_by(Scan.created_at.desc()).all()


@reports_bp.route('/history')
@login_required
def history():
    """Shows the current user's scan history, optionally filtered, paginated."""
    selected_type = request.args.get('type', '')
    page = request.args.get('page', 1, type=int)

    query = Scan.query.filter_by(user_id=current_user.id)
    if selected_type in VALID_SCAN_TYPES:
        query = query.filter_by(scan_type=selected_type)
    query = query.order_by(Scan.created_at.desc())

    pagination = query.paginate(page=page, per_page=SCANS_PER_PAGE, error_out=False)

    return render_template(
        'reports/history.html',
        scans=pagination.items,
        pagination=pagination,
        selected_type=selected_type,
        valid_types=VALID_SCAN_TYPES
    )


@reports_bp.route('/reports/export/csv')
@login_required
def export_csv():
    """Exports the user's (optionally filtered) scan history as a CSV file."""
    selected_type = request.args.get('type', '')
    scans = get_filtered_scans(selected_type)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Date', 'Scan Type', 'Target', 'Result'])

    for scan in scans:
        writer.writerow([
            scan.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            scan.scan_type,
            scan.target,
            scan.result or ''
        ])

    # Convert the text buffer to bytes, since send_file expects a bytes stream
    byte_output = io.BytesIO(output.getvalue().encode('utf-8'))
    output.close()

    filename = f"scan_history_{current_user.username}.csv"
    return send_file(
        byte_output,
        mimetype='text/csv',
        as_attachment=True,
        download_name=filename
    )


@reports_bp.route('/reports/export/pdf')
@login_required
def export_pdf():
    """Exports the user's (optionally filtered) scan history as a PDF report."""
    selected_type = request.args.get('type', '')
    scans = get_filtered_scans(selected_type)

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(letter))
    styles = getSampleStyleSheet()
    elements = []

    title_text = f"Scan History Report -- {current_user.username}"
    if selected_type:
        title_text += f" ({selected_type.capitalize()} only)"
    elements.append(Paragraph(title_text, styles['Title']))
    elements.append(Spacer(1, 0.2 * inch))

    # Table header + rows. Result text is truncated so rows stay a
    # reasonable height -- the CSV export has the full untruncated text.
    table_data = [['Date', 'Type', 'Target', 'Result']]
    for scan in scans:
        result_text = (scan.result or '')[:120]
        if scan.result and len(scan.result) > 120:
            result_text += '...'
        table_data.append([
            scan.created_at.strftime('%Y-%m-%d %H:%M'),
            scan.scan_type.capitalize(),
            (scan.target or '')[:60],
            result_text
        ])

    table = Table(table_data, colWidths=[1.3 * inch, 1 * inch, 2.5 * inch, 4.2 * inch])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#212529')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f2f2f2')]),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    elements.append(table)

    doc.build(elements)
    buffer.seek(0)

    filename = f"scan_history_{current_user.username}.pdf"
    return send_file(
        buffer,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=filename
    )
