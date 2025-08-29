from flask import Flask, render_template, request, jsonify
from Stage_1_Filtering.pipeline import Stage1Pipeline
import tempfile
import os
import pdfplumber
from docx import Document

app = Flask(__name__)
pipeline = Stage1Pipeline()

def extract_text_from_pdf(file_path):
    with pdfplumber.open(file_path) as pdf:
        text = ""
        for page in pdf.pages:
            text += page.extract_text() or ""
    return text

def extract_text_from_docx(file_path):
    doc = Document(file_path)
    return "\n".join(para.text for para in doc.paragraphs)

@app.route('/')
def index():
    return render_template('index2.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    input_type = request.form.get('input_type')
    try:
        if input_type == 'text':
            text = request.form.get('content')
            title = request.form.get('title', '')
            result = pipeline.process_text(text, title)
        elif input_type == 'url':
            url = request.form.get('content')
            result = pipeline.process_url(url)
        elif input_type == 'file':
            uploaded_file = request.files['file']
            _, temp_path = tempfile.mkstemp()
            uploaded_file.save(temp_path)
            if uploaded_file.filename.endswith('.pdf'):
                text = extract_text_from_pdf(temp_path)
            elif uploaded_file.filename.endswith('.docx'):
                text = extract_text_from_docx(temp_path)
            else:
                with open(temp_path, 'r') as f:
                    text = f.read()
            result = pipeline.process_text(text)
            os.remove(temp_path)
        else:
            return jsonify({'status': 'error', 'message': 'Unknown input type'})
        
        if result is None:
            return jsonify({'status': 'error', 'message': 'Failed to process input'})
        
        return jsonify({
            'status': 'success',
            'result': simplify_result(result)
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

def simplify_result(full_result):
    return {
        'domain': full_result.get('domain'),
        'title': full_result.get('title'),
        'risk_score': full_result.get('overall_authenticity_score', 0) * 100 if 'overall_authenticity_score' in full_result else 0,
        'verdict': 'Genuine' if full_result.get('ready_for_stage2') else 'Fake',
        'warnings': full_result.get('filter_reason') or full_result.get('rule_reason'),
        'detailed_analysis': {
            'source_trust': full_result.get('source_trust_score', 0),
            'content_trust': full_result.get('content_trust_score', 0),
            'linguistic_analysis': full_result.get('content_tokens', [])[:20] if 'content_tokens' in full_result else [],
            'domain_check': full_result.get('domain_check')
        }
    }

if __name__ == '__main__':
    app.run(debug=True)