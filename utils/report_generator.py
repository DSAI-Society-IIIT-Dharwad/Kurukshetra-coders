from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from datetime import datetime
import logging
import io

logger = logging.getLogger(__name__)

class ReportGenerator:
    def _init_(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Setup custom styles for the report"""
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=30,
            alignment=TA_CENTER
        ))
        
        severity_colors = {
            'CRITICAL': colors.HexColor('#dc2626'),
            'HIGH': colors.HexColor('#ea580c'),
            'MEDIUM': colors.HexColor('#ca8a04'),
            'LOW': colors.HexColor('#16a34a')
        }
        
        for severity, color in severity_colors.items():
            self.styles.add(ParagraphStyle(
                name=f'Severity{severity}',
                parent=self.styles['Normal'],
                textColor=color,
                fontSize=12,
                fontName='Helvetica-Bold'
            ))
    
    def generate(self, scan_result_dict):
        """Generate PDF report from scan results"""
        try:
            buffer = io.BytesIO()
            doc = SimpleDocTemplate(
                buffer, 
                pagesize=letter,
                rightMargin=72, 
                leftMargin=72,
                topMargin=72, 
                bottomMargin=18
            )
            
            story = []
            
            # Title
            title = Paragraph(
                "Security Vulnerability Assessment Report", 
                self.styles['CustomTitle']
            )
            story.append(title)
            story.append(Spacer(1, 0.5*inch))
            
            # Executive Summary
            story.append(Paragraph("Executive Summary", self.styles['Heading1']))
            story.append(Spacer(1, 0.2*inch))
            
            # Scan details
            scan_info = [
                ['Target URL:', scan_result_dict.get('url', 'N/A')],
                ['Scan Date:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
                ['Security Score:', f"{scan_result_dict.get('security_score', 0)}/100"],
                ['Total Vulnerabilities:', str(scan_result_dict.get('total_vulnerabilities', 0))],
                ['Status:', scan_result_dict.get('status', 'Unknown').upper()]
            ]
            
            scan_table = Table(scan_info, colWidths=[2*inch, 4*inch])
            scan_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f3f4f6')),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey)
            ]))
            
            story.append(scan_table)
            story.append(Spacer(1, 0.3*inch))
            
            # Severity breakdown
            story.append(Paragraph("Severity Breakdown", self.styles['Heading2']))
            story.append(Spacer(1, 0.2*inch))
            
            severity_breakdown = scan_result_dict.get('severity_breakdown', {})
            severity_data = [
                ['Severity Level', 'Count'],
                ['Critical', str(severity_breakdown.get('CRITICAL', 0))],
                ['High', str(severity_breakdown.get('HIGH', 0))],
                ['Medium', str(severity_breakdown.get('MEDIUM', 0))],
                ['Low', str(severity_breakdown.get('LOW', 0))]
            ]
            
            severity_table = Table(severity_data, colWidths=[3*inch, 3*inch])
            severity_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3b82f6')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f9fafb')])
            ]))
            
            story.append(severity_table)
            story.append(Spacer(1, 0.5*inch))
            
            # Detailed Findings
            story.append(PageBreak())
            story.append(Paragraph("Detailed Findings", self.styles['Heading1']))
            story.append(Spacer(1, 0.3*inch))
            
            vulnerabilities = scan_result_dict.get('vulnerabilities', [])
            
            if not vulnerabilities:
                story.append(Paragraph(
                    "No vulnerabilities detected. The application appears to be secure.",
                    self.styles['Normal']
                ))
            else:
                for idx, vuln in enumerate(vulnerabilities, 1):
                    # Vulnerability title
                    vuln_title = f"{idx}. {vuln.get('type', 'Unknown').replace('_', ' ').title()}"
                    story.append(Paragraph(vuln_title, self.styles['Heading2']))
                    story.append(Spacer(1, 0.1*inch))
                    
                    # Severity badge
                    severity = vuln.get('severity', 'MEDIUM')
                    severity_color = self._get_severity_color(severity)
                    severity_text = f"<b>Severity:</b> <font color='#{severity_color}'>{severity}</font>"
                    story.append(Paragraph(severity_text, self.styles['Normal']))
                    story.append(Spacer(1, 0.1*inch))
                    
                    # Description
                    story.append(Paragraph("<b>Description:</b>", self.styles['Normal']))
                    description = vuln.get('description', 'No description available.')
                    # Escape XML special characters
                    description = self._escape_xml(description)
                    story.append(Paragraph(description, self.styles['Normal']))
                    story.append(Spacer(1, 0.1*inch))
                    
                    # Evidence
                    evidence = vuln.get('evidence', {})
                    if evidence:
                        story.append(Paragraph("<b>Evidence:</b>", self.styles['Normal']))
                        for key, value in evidence.items():
                            # Convert value to string and escape XML
                            value_str = self._escape_xml(str(value))
                            key_formatted = key.replace('_', ' ').title()
                            evidence_text = f"• {key_formatted}: {value_str}"
                            story.append(Paragraph(evidence_text, self.styles['Normal']))
                        story.append(Spacer(1, 0.1*inch))
                    
                    # Recommendation
                    story.append(Paragraph("<b>Recommendation:</b>", self.styles['Normal']))
                    recommendation = vuln.get('recommendation', 'No recommendation available.')
                    # Escape XML special characters
                    recommendation = self._escape_xml(recommendation)
                    story.append(Paragraph(recommendation, self.styles['Normal']))
                    
                    story.append(Spacer(1, 0.3*inch))
                    
                    # Add page break after every 3 vulnerabilities
                    if idx % 3 == 0 and idx < len(vulnerabilities):
                        story.append(PageBreak())
            
            # Recommendations Summary
            story.append(PageBreak())
            story.append(Paragraph("Recommendations Summary", self.styles['Heading1']))
            story.append(Spacer(1, 0.2*inch))
            
            recommendations_text = """
            <b>Immediate Actions Required:</b><br/>
            1. Address all CRITICAL and HIGH severity vulnerabilities immediately<br/>
            2. Implement missing security headers<br/>
            3. Update outdated software and frameworks<br/>
            4. Remove exposed sensitive files<br/>
            5. Conduct regular security assessments<br/><br/>
            
            <b>Best Practices:</b><br/>
            • Keep all software and dependencies up to date<br/>
            • Implement a Web Application Firewall (WAF)<br/>
            • Use HTTPS for all communications<br/>
            • Regular security audits and penetration testing<br/>
            • Security awareness training for development team<br/>
            • Implement proper input validation and output encoding<br/>
            • Use security headers to protect against common attacks<br/>
            """
            
            story.append(Paragraph(recommendations_text, self.styles['Normal']))
            story.append(Spacer(1, 0.3*inch))
            
            # Footer
            story.append(Spacer(1, 0.5*inch))
            footer_text = f"""
            <i>This report was generated on {datetime.now().strftime('%B %d, %Y at %I:%M %p')} 
            by VulnScanner - Automated Vulnerability Assessment Tool.</i>
            """
            story.append(Paragraph(footer_text, self.styles['Normal']))
            
            # Build PDF
            doc.build(story)
            
            # Get PDF data
            pdf_data = buffer.getvalue()
            buffer.close()
            
            return pdf_data
        
        except Exception as e:
            logger.error(f"Error generating report: {e}")
            return None
    
    def _get_severity_color(self, severity):
        """Get color code for severity level"""
        colors_map = {
            'CRITICAL': 'dc2626',
            'HIGH': 'ea580c',
            'MEDIUM': 'ca8a04',
            'LOW': '16a34a'
        }
        return colors_map.get(severity, '6b7280')
    
    def _escape_xml(self, text):
        """Escape XML special characters for ReportLab"""
        if not text:
            return ''
        text = str(text)
        text = text.replace('&', '&amp;')
        text = text.replace('<', '&lt;')
        text = text.replace('>', '&gt;')
        text = text.replace('"', '&quot;')
        text = text.replace("'", '&apos;')
        return text