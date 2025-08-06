from langchain.document_loaders import PyPDFLoader
import logging
import os


def process_pdf_file(file_path):
    logging.info(f"Processing PDF file: {file_path}")
    print(f"[DEBUG] process_pdf_file: Processing {file_path}")
    
    try:
        # Verify file exists and has content
        if not os.path.exists(file_path):
            print(f"[DEBUG] ERROR: File does not exist: {file_path}")
            raise FileNotFoundError(f"File does not exist: {file_path}")
            
        file_size = os.path.getsize(file_path)
        print(f"[DEBUG] File size: {file_size} bytes")
        
        if file_size == 0:
            print(f"[DEBUG] WARNING: File is empty: {file_path}")
            logging.warning(f"File is empty: {file_path}")
        
        # Use PyPDFLoader with the saved file path
        loader = PyPDFLoader(file_path)
        pages = loader.load()
        
        print(f"[DEBUG] Extracted {len(pages)} pages from {file_path}")
        
        # Print content from each page for debugging
        for i, page in enumerate(pages):
            content_length = len(page.page_content)
            logging.info(f"Page {i+1} content length: {content_length}")
            print(f"[DEBUG] Page {i+1} content length: {content_length}")
            
            # Print sample of content for verification
            if content_length > 0:
                sample = page.page_content[:100] + "..." if content_length > 100 else page.page_content
                print(f"[DEBUG] Page {i+1} content sample: {sample}")
            else:
                print(f"[DEBUG] WARNING: Page {i+1} is empty")
            
        return pages
    except Exception as e:
        print(f"[DEBUG] Error processing PDF file: {str(e)}")
        logging.error(f"Error processing PDF file: {str(e)}")
        raise
