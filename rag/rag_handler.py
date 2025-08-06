import os
import uuid
import json
import base64
import logging
import numpy as np
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from pathlib import Path
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import Chroma
from langchain_core.embeddings import Embeddings
from llm.openai_module import OpenAIHandler
from utils.config import get_llm_method
from utils.storage import StorageHandler

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

@dataclass
class Prompt:
    system_context: str
    task: str
    query: Optional[str] = None
    format: Optional[Any] = None
    example: Optional[str] = None
    instructions: Optional[str] = None

class PromptManager:
    def __init__(self, prompt_file: str = "rag/prompts.json"):
        self.prompts: Dict[str, Prompt] = {}
        self._load_prompts(prompt_file)

    def _load_prompts(self, prompt_file: str) -> None:
        try:
            with open(prompt_file, 'r') as f:
                data = json.load(f)
                self.prompts = {
                    key: Prompt(**value) for key, value in data.items()
                }
        except Exception as e:
            logging.error(f"Error loading prompts: {e}")
            raise

    def get_prompt(self, key: str, **kwargs) -> Prompt:
        prompt = self.prompts.get(key)
        if not prompt:
            raise ValueError(f"Prompt '{key}' not found")
        
        # Handle any string formatting in the prompt
        if kwargs:
            prompt.task = prompt.task.format(**kwargs)
            if prompt.query:
                prompt.query = prompt.query.format(**kwargs)
        return prompt

class CustomEmbeddings(Embeddings):
    """Custom embeddings class that implements LangChain's Embeddings interface."""
    
    def __init__(self, client, method):
        self.client = client
        self.method = method
        
    def embed_documents(self, texts: List[str]) -> List[List[float]]:
        """Get embeddings for a list of texts."""
        try:
            logging.info(f"Getting embeddings for {len(texts)} texts using {self.method}")
            
            # Prepare common parameters
            params = {
                "model": "text-embedding-3-large" if self.method == 'OPENAI' else "text-embedding-3-large",
                "input": texts
            }
            
            # Make the API call
            response = self.client.embeddings.create(**params)
            
            # Extract embeddings from response
            embeddings = [data.embedding for data in response.data]
            logging.info(f"Successfully generated {len(embeddings)} embeddings")
            
            return embeddings
            
        except Exception as e:
            error_msg = f"Error getting embeddings from {self.method}: {str(e)}"
            logging.error(error_msg)
            raise RuntimeError(error_msg)
            
    def embed_query(self, text: str) -> List[float]:
        """Get embedding for a single text."""
        return self.embed_documents([text])[0]

class RAGHandler:
    def __init__(self, openai_handler: OpenAIHandler, persist_dir: str, assessment_id: str, table_name: str = "docs"):
        self.openai_handler = openai_handler
        self.persist_dir = str(Path(persist_dir) / str(uuid.uuid4()))
        self.table_name = table_name
        self.prompt_manager = PromptManager()
        self.client = openai_handler.client
        self.method = get_llm_method()
        self.storage_handler = StorageHandler()
        self.assessment_id = assessment_id
        logging.info(f"Initializing RAG with {self.method} method for assessment {assessment_id}")

        # Create proper embedding class for Chroma
        self.embeddings = CustomEmbeddings(self.client, self.method)

    def get_completion(self, prompt: str, max_tokens: int = 1000) -> str:
        """Get completion from the LLM."""
        try:
            logging.info(f"Getting completion from {self.method} using model {self.openai_handler.model}")
            
            # Prepare common parameters
            params = {
                "model": self.openai_handler.model,
                "messages": [
                    {"role": "user", "content": prompt}
                ],
                "max_tokens": max_tokens
            }
            
            # Add provider-specific parameters
            if self.method == 'OPENAI':
                params["temperature"] = 0.1
            elif self.method == 'BEDROCK':
                # Bedrock might have different parameters
                pass
            
            # Make the API call
            response = self.client.chat.completions.create(**params)
            
            # Extract and return the response content
            return response.choices[0].message.content.strip()
            
        except Exception as e:
            error_msg = f"Error getting completion from {self.method}: {str(e)}"
            logging.error(error_msg)
            raise RuntimeError(error_msg)

    def split_documents(self, documents: List[Any]) -> List[Any]:
        """Split documents into chunks for processing."""
        # Validate input documents
        if not documents:
            print("[DEBUG] ERROR: Empty document list provided to split_documents")
            raise ValueError("Empty document list provided")
            
        print(f"[DEBUG] split_documents: Processing {len(documents)} documents")
            
        # Log document content for debugging
        for i, doc in enumerate(documents):
            content = doc.page_content if hasattr(doc, 'page_content') else str(doc)
            content_length = len(content)
            logging.info(f"Document {i+1} content length: {content_length}")
            print(f"[DEBUG] Document {i+1} content length: {content_length}")
            
            if content_length > 0:
                sample = content[:100] + "..." if content_length > 100 else content
                logging.info(f"Document {i+1} first 100 chars: {content[:100]}")
                print(f"[DEBUG] Document {i+1} first 100 chars: {sample}")
            else:
                logging.warning(f"Document {i+1} is empty")
                print(f"[DEBUG] WARNING: Document {i+1} is empty")
                
        # Use a simpler text splitter with larger chunks
        text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=2000,  # Larger chunks
            chunk_overlap=100,  # Smaller overlap
            separators=["\n\n", "\n", ".", " ", ""],  # More granular separators
            keep_separator=True
        )
        print(f"[DEBUG] Using text splitter with chunk_size=2000, chunk_overlap=100")
        
        # Process each document individually to ensure proper chunking
        all_splits = []
        for i, doc in enumerate(documents):
            try:
                # Extract text content from the document
                text = doc.page_content if hasattr(doc, 'page_content') else str(doc)
                if not text.strip():
                    logging.warning(f"Document {i+1} contains only whitespace")
                    print(f"[DEBUG] WARNING: Document {i+1} contains only whitespace")
                    continue
                
                print(f"[DEBUG] Splitting document {i+1} with length {len(text)}")
                
                # Split text into chunks first
                text_chunks = text_splitter.split_text(text)
                if not text_chunks:
                    logging.warning(f"Document {i+1} generated no text chunks")
                    print(f"[DEBUG] WARNING: Document {i+1} generated no text chunks")
                    continue
                    
                print(f"[DEBUG] Document {i+1} split into {len(text_chunks)} text chunks")
                    
                # Create documents from chunks with metadata
                doc_chunks = []
                for j, chunk in enumerate(text_chunks):
                    if chunk.strip():  # Only create documents for non-empty chunks
                        doc_chunks.append({
                            "page_content": chunk,
                            "metadata": {
                                "source": f"document_{i+1}",
                                "chunk": j+1,
                                "total_chunks": len(text_chunks)
                            }
                        })
                
                if doc_chunks:
                    all_splits.extend(doc_chunks)
                    logging.info(f"Document {i+1} split into {len(doc_chunks)} chunks")
                    print(f"[DEBUG] Document {i+1} created {len(doc_chunks)} document chunks")
                    
                    # Print sample of first chunk
                    first_chunk = doc_chunks[0]['page_content']
                    sample = first_chunk[:100] + "..." if len(first_chunk) > 100 else first_chunk
                    logging.info(f"First chunk content sample: {first_chunk[:100]}")
                    print(f"[DEBUG] First chunk content sample: {sample}")
                    
            except Exception as e:
                logging.error(f"Error splitting document {i+1}: {str(e)}")
                print(f"[DEBUG] ERROR splitting document {i+1}: {str(e)}")
                continue
                
        if not all_splits:
            print("[DEBUG] ERROR: No valid chunks were generated from the documents")
            raise ValueError("No valid chunks were generated from the documents. Check if the documents contain extractable text content.")
            
        logging.info(f"Total: Created {len(all_splits)} chunks from {len(documents)} documents")
        print(f"[DEBUG] Total: Created {len(all_splits)} chunks from {len(documents)} documents")
        return all_splits

    def create_vector_db(self, documents: List[Any]) -> Chroma:
        """Create or load vector database."""
        logging.info(f"Creating or loading vector database for {self.persist_dir}")
        print(f"[DEBUG] Creating or loading vector database for {self.persist_dir}")
        
        if not documents:
            print("[DEBUG] ERROR: No documents provided for vector database creation")
            raise ValueError("No documents provided for vector database creation")
            
        print(f"[DEBUG] Processing {len(documents)} documents for vector database")
            
        # Convert document dictionaries to Document objects if needed
        from langchain_core.documents import Document
        processed_docs = []
        for i, doc in enumerate(documents):
            if isinstance(doc, dict):
                processed_docs.append(Document(
                    page_content=doc["page_content"],
                    metadata=doc.get("metadata", {})
                ))
            else:
                processed_docs.append(doc)
                
        print(f"[DEBUG] Converted {len(processed_docs)} documents to Document objects")
                
        if os.path.exists(self.persist_dir):
            print(f"[DEBUG] Loading existing vector database from {self.persist_dir}")
            db = Chroma(
                persist_directory=self.persist_dir,
                embedding_function=self.embeddings,
                collection_name=self.table_name
            )
            doc_count = db._collection.count()
            logging.info(f"Loaded existing vector database with {doc_count} documents")
            print(f"[DEBUG] Loaded existing vector database with {doc_count} documents")
            return db
        
        # Create new database with processed documents
        try:
            print(f"[DEBUG] Creating new vector database with {len(processed_docs)} documents")
            db = Chroma.from_documents(
                documents=processed_docs,
                embedding=self.embeddings,
                persist_directory=self.persist_dir,
                collection_metadata={"hnsw:space": "cosine"},
                collection_name=self.table_name
            )
            doc_count = db._collection.count()
            logging.info(f"Created new vector database with {doc_count} documents")
            print(f"[DEBUG] Successfully created new vector database with {doc_count} documents")
            
            if doc_count == 0:
                print("[DEBUG] ERROR: Vector database was created but contains no documents")
                raise ValueError("Vector database was created but contains no documents")
                
            return db
            
        except Exception as e:
            logging.error(f"Error creating vector database: {str(e)}")
            print(f"[DEBUG] ERROR creating vector database: {str(e)}")
            if os.path.exists(self.persist_dir):
                import shutil
                shutil.rmtree(self.persist_dir)  # Clean up failed database
            raise

    def setup_documents(self, documents: List[Any]) -> None:
        """Set up documents for retrieval."""
        if not documents:
            logging.error("No documents provided for RAG setup")
            print("[DEBUG] ERROR: No documents provided for RAG setup")
            raise ValueError("Documents list is empty")
            
        logging.info(f"Processing {len(documents)} documents")
        print(f"[DEBUG] setup_documents: Processing {len(documents)} documents")
        
        # Print document types for debugging
        doc_types = [type(doc).__name__ for doc in documents]
        print(f"[DEBUG] Document types: {doc_types}")
        
        # Split documents into chunks
        print("[DEBUG] Splitting documents into chunks...")
        splits = self.split_documents(documents)
        
        if not splits:
            logging.error("Document splitting resulted in empty chunks")
            print("[DEBUG] ERROR: Document splitting resulted in empty chunks")
            raise ValueError("No text chunks generated from documents")
            
        logging.info(f"Created {len(splits)} text chunks")
        print(f"[DEBUG] Created {len(splits)} text chunks")
        
        # Create vector database
        print("[DEBUG] Creating vector database...")
        self.vectordb = self.create_vector_db(splits)
        print(f"[DEBUG] Vector database created with {self.vectordb._collection.count()} documents")

    def get_context(self, query: str) -> str:
        """Get context from vector database using query."""
        # Get collection size and adjust k accordingly
        collection_size = self.vectordb._collection.count()
        k = min(10, collection_size)
        logging.info(f"Retrieving {k} documents from a collection of {collection_size} documents")
        print(f"[DEBUG] get_context: Retrieving {k} documents from a collection of {collection_size} documents")
        print(f"[DEBUG] Query: {query[:100]}..." if len(query) > 100 else f"[DEBUG] Query: {query}")
        
        retriever = self.vectordb.as_retriever(
            search_type="similarity", 
            search_kwargs={"k": k}
        )
        docs = retriever.get_relevant_documents(query)
        logging.info(f"Retrieved {len(docs)} relevant documents")
        print(f"[DEBUG] Retrieved {len(docs)} relevant documents")
        
        # Print sample of retrieved documents
        for i, doc in enumerate(docs[:3]):  # Print first 3 docs only
            content = doc.page_content
            sample = content[:100] + "..." if len(content) > 100 else content
            print(f"[DEBUG] Retrieved doc {i+1} sample: {sample}")
            
        context = "".join(doc.page_content for doc in docs)
        print(f"[DEBUG] Total context length: {len(context)} characters")
        return context

    def ask_ai(self, prompt_key: str, context: str, **kwargs) -> str:
        """Ask AI using prompt template and context."""
        try:
            prompt_data = self.prompt_manager.get_prompt(prompt_key, **kwargs)
            
            # Build system message with format instructions if available
            system_template = f"{prompt_data.system_context}\nONLY use provided context = {context} to answer."
            if prompt_data.format:
                if isinstance(prompt_data.format, list):
                    format_str = "\n".join(prompt_data.format)
                    system_template += f"\n\nRequired format:\n{format_str}"
                else:
                    system_template += f"\n\nRequired format: {prompt_data.format}"
            
            if prompt_data.example:
                system_template += f"\n\nExample: {prompt_data.example}"
            
            # Prepare messages for the API call
            messages = [
                {"role": "system", "content": system_template},
                {"role": "user", "content": f"{prompt_data.task}\n<question>{prompt_data.task}</question>"}
            ]
            
            # Prepare common parameters
            params = {
                "model": self.openai_handler.model,
                "messages": messages,
                "max_tokens": 2000
            }
            
            # Add provider-specific parameters
            if self.method == 'OPENAI':
                params["temperature"] = 0.1
            elif self.method == 'BEDROCK':
                # Bedrock might have different parameters
                pass
            
            # Make the API call
            response = self.client.chat.completions.create(**params)
            
            # Extract and return the response content
            return response.choices[0].message.content.strip()
            
        except Exception as e:
            error_msg = f"Error in ask_ai: {str(e)}"
            logging.error(error_msg)
            raise RuntimeError(error_msg)

    def process_section(self, section_key: str, **kwargs) -> str:
        """Process a section using its prompt and context."""
        prompt_data = self.prompt_manager.get_prompt(section_key)
        if not prompt_data.query:
            return self.ask_ai(section_key, "", **kwargs)
            
        context = self.get_context(prompt_data.query)
        return self.ask_ai(section_key, context, **kwargs)

    def analyze_architecture_diagram(self, encoded_image: str) -> Dict[str, Any]:
        """Analyze architecture diagram and extract microservices."""
        try:
            prompt_data = self.prompt_manager.get_prompt("architecture_analysis")
            
            # Create system message with format requirements
            system_message = f"{prompt_data.system_context} \n Required output format: {prompt_data.format}"
            
            # Prepare messages for the API call
            messages = [
                {"role": "system", "content": system_message},
                {
                    "role": "user", 
                    "content": [
                        {"type": "image_url", "image_url": f"data:image/jpeg;base64,{encoded_image}"},
                        {"type": "text", "text": prompt_data.task}
                    ]
                }
            ]
            
            # Prepare common parameters
            params = {
                "model": self.openai_handler.model,
                "messages": messages,
                "max_tokens": 2000
            }
            
            # Add provider-specific parameters
            if self.method == 'OPENAI':
                params["temperature"] = 0.1
                params["response_format"] = {"type": "json_object"}
            elif self.method == 'BEDROCK':
                # Bedrock might have different parameters
                pass
            
            # Make the API call
            response = self.client.chat.completions.create(**params)
            
            # Extract and clean the response content
            services = response.choices[0].message.content.strip()
            logging.info(f"Raw LLM response: {services}")
            
            # Clean and validate JSON
            cleaned_json = services.replace("```json", "").replace("```", "").strip()
            try:
                json_services = json.loads(cleaned_json)
                
                # Strict format validation
                if not isinstance(json_services, dict):
                    raise ValueError("Response must be a JSON object")
                if "services" not in json_services:
                    raise ValueError("Response must have a 'services' key")
                if not isinstance(json_services["services"], list):
                    raise ValueError("'services' must be an array")
                if not json_services["services"]:
                    raise ValueError("'services' array cannot be empty")
                if not all(isinstance(s, dict) and len(s) == 1 and "Name" in s and isinstance(s["Name"], str) for s in json_services["services"]):
                    raise ValueError("Each service must be an object with exactly one 'Name' field containing a string")
                    
                logging.info(f"Parsed services: {json_services}")
                
                # Create files directory if it doesn't exist
                os.makedirs("files", exist_ok=True)
                self.save_to_file("files/microservices.json", json_services)
                return json_services
                
            except json.JSONDecodeError as e:
                logging.error(f"JSON parsing error: {e}")
                logging.error(f"Attempted to parse: {cleaned_json}")
                raise ValueError(f"Failed to parse LLM response as JSON: {e}")
                
        except Exception as e:
            logging.error(f"Error in architecture diagram analysis: {e}")
            raise

    def encode_image(self, image_path: str) -> str:
        """Encode image file to base64 string."""
        if not os.path.exists(image_path):
            raise FileNotFoundError(f"Image file not found: {image_path}")
            
        try:
            with open(image_path, "rb") as image_file:
                return base64.b64encode(image_file.read()).decode("utf-8")
        except Exception as e:
            logging.error(f"Error encoding image {image_path}: {e}")
            raise

    def rag_image(self, path: str) -> Dict[str, Any]:
        """Process RAG image and extract services."""
        encoded_image = self.encode_image(path)
        return self.analyze_architecture_diagram(encoded_image)

    def save_to_file(self, filepath: str, content: Any, mode: str = "w") -> None:
        """Save content to file with proper error handling."""
        try:
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            with open(filepath, mode, encoding="utf-8") as f:
                if isinstance(content, dict):
                    json.dump(content, f, indent=4)
                else:
                    f.write(f"{content}\n")
        except Exception as e:
            logging.error(f"Error saving to file: {e}")
            raise

    def append_to_file(self, content: str) -> None:
        """Append content to output report."""
        self.save_to_file("files/outputreport.txt", content, mode="a")

    def rag_main(self, documents: List[Any]) -> str:
        """Main RAG process with optimized document processing."""
        logging.info("Starting RAG main process")
        print(f"[DEBUG] rag_main: Starting RAG process with {len(documents)} documents")
        
        # Setup documents for RAG
        print("[DEBUG] Setting up documents for RAG...")
        self.setup_documents(documents)
        prompt = ""
        
        # Cache the vector database size
        collection_size = self.vectordb._collection.count()
        if collection_size == 0:
            print("[DEBUG] ERROR: No documents were successfully processed and embedded")
            raise ValueError("No documents were successfully processed and embedded")
        logging.info(f"Working with {collection_size} document chunks")
        print(f"[DEBUG] Working with {collection_size} document chunks in vector database")
        
        # Process main sections with cached context
        sections = ["introduction", "functional_flows", "third_party_integrations"]
        section_contexts = {}
        section_results = {}
        
        # First, get all contexts to avoid repeated retrievals
        for section in sections:
            prompt_data = self.prompt_manager.get_prompt(section)
            if prompt_data.query:
                section_contexts[section] = self.get_context(prompt_data.query)
        
        # Then process each section using cached contexts
        for section in sections:
            section_header = f"\n# {section.replace('_', ' ').title()}\n"
            self.append_to_file(section_header)
            prompt += section_header
            
            context = section_contexts.get(section, "")
            result = self.ask_ai(section, context)
            # Store the result without the section header
            if section in ["functional_flows", "third_party_integrations"]:
                # Remove any duplicate section headers that might be in the result
                clean_result = result.replace(f"# {section.replace('_', ' ').title()}\n", "")
                clean_result = clean_result.replace(f"# {section.replace('_', ' ').title()}", "")
                section_results[section] = clean_result.strip()
            else:
                section_results[section] = result
            self.append_to_file(result)
            prompt += result

        # Update additionalinfo.json with functional_flows and third_party_integrations
        try:
            # Get existing additionalinfo.json content
            additional_info_path = os.path.join('storage', self.assessment_id, 'additionalinfo.json')
            
            if os.path.exists(additional_info_path):
                with open(additional_info_path, 'r') as f:
                    enhanced_info = json.load(f)
            else:
                enhanced_info = {
                }
            
            # Update with new sections while preserving existing data
            enhanced_info["functional_flows"] = section_results.get("functional_flows")
            enhanced_info["third_party_integrations"] = section_results.get("third_party_integrations")
            
            # Save updated info using storage handler
            os.makedirs(os.path.dirname(additional_info_path), exist_ok=True)
            with open(additional_info_path, 'w') as f:
                json.dump(enhanced_info, f, indent=2)
                
            logging.info(f"Successfully updated additionalinfo.json for assessment {self.assessment_id}")
            
        except Exception as e:
            logging.error(f"Error updating additionalinfo.json for assessment {self.assessment_id}: {str(e)}")

        # Process microservice summaries
        ms_header = "\n# Microservice Summaries\n"
        self.append_to_file(ms_header)
        prompt += ms_header

        try:
            with open("files/microservices.json", "r", encoding="utf-8") as f:
                services = json.load(f)
                service_names = [service["Name"] for service in services["services"]]

                # Cache contexts for all services first
                service_contexts = {}
                for service in service_names:
                    prompt_data = self.prompt_manager.get_prompt("microservice_summary")
                    if prompt_data.query:
                        query = prompt_data.query.format(service=service)
                        service_contexts[service] = self.get_context(query)

                # Then process each service using cached contexts
                for service in service_names:
                    service_header = f"\n## {service} Microservice\n"
                    self.append_to_file(service_header)
                    prompt += service_header
                    
                    context = service_contexts.get(service, "")
                    result = self.ask_ai("microservice_summary", context, service=service)
                    self.append_to_file(result)
                    prompt += result
                    
        except Exception as e:
            logging.error(f"Error processing microservices: {e}")
            raise

        logging.info("RAG main process completed")
        return prompt
