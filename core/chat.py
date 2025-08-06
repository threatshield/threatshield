from utils.storage import StorageHandler
from llm.openai_module import OpenAI, OpenAIHandler
from langchain_core.memory import BaseMemory
from langchain_core.messages import HumanMessage, AIMessage
from core.dread import DreadHandler
from core.mitigation import MitigationHandler
from core.attack_tree import AttackTreeHandler
import json
import logging
import datetime
import os

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class Chat:
    def __init__(self, openai_handler):
        self.openai_handler = openai_handler
        self.client = openai_handler.client
        self.storage_handler = StorageHandler()
        self.context = {}  # Dictionary to store context by assessment_id
        self.conversation_history = {}  # Dictionary to store conversation history by assessment_id
        self.MAX_HISTORY_MESSAGES = 10  # Limit chat history to last 10 messages
        
        # Initialize security analysis handlers
        self.dread_handler = DreadHandler(openai_handler)
        self.mitigation_handler = MitigationHandler(openai_handler)
        self.attack_tree_handler = AttackTreeHandler(openai_handler)
        
        # Load prompts from JSON file
        self.prompts = self._load_prompts()
    
    def _load_prompts(self):
        """Load prompts from the prompts.json file"""
        try:
            prompts_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'rag', 'prompts.json')
            with open(prompts_path, 'r') as f:
                prompts = json.load(f)
            logging.info(f'Successfully loaded prompts from {prompts_path}')
            return prompts
        except Exception as e:
            logging.error(f'Error loading prompts: {str(e)}')
            return {}

    def _get_conversation_history(self, assessment_id):
        """Get conversation history for a specific assessment"""
        if assessment_id not in self.conversation_history:
            self.conversation_history[assessment_id] = []
        return self.conversation_history[assessment_id]

    def _add_to_conversation_history(self, assessment_id, role, content):
        """Add a message to the conversation history"""
        history = self._get_conversation_history(assessment_id)
        history.append({"role": role, "content": content})
        
        # Keep only recent messages
        if len(history) > self.MAX_HISTORY_MESSAGES:
            self.conversation_history[assessment_id] = history[-self.MAX_HISTORY_MESSAGES:]

    def _truncate_context(self, context, max_chars=10000):
        """Truncate context if it's too long"""
        if len(context) > max_chars:
            logging.warning(f'Context too long ({len(context)} chars), truncating to {max_chars} chars')
            return context[:max_chars] + "...[truncated for length]"
        return context

    def _load_context(self, assessment_id):
        """Load and prepare comprehensive context from all available data sources"""
        context_data = {}
        
        # Load all relevant data types
        for name in ["threat_model", "dread_assessment", "mitigation", "attack_tree", "rag_result", "test_cases"]:
            result = self.storage_handler.retrive_from_storage(assessment_id=assessment_id, assessment_name=name)
            if result and 'result' in result:
                context_data[name] = result['result']
        
        # Process and structure the context
        structured_context = {
            "threat_model": self._extract_threat_model_summary(context_data.get("threat_model", {})),
            "dread_assessment": self._extract_dread_summary(context_data.get("dread_assessment", {})),
            "mitigations": self._extract_mitigation_summary(context_data.get("mitigation", {})),
            "attack_tree": self._extract_attack_tree_summary(context_data.get("attack_tree", {})),
            "additional_context": context_data.get("rag_result", {}),
            "test_cases": context_data.get("test_cases", {}),
            "raw_data": context_data  # Keep raw data for special processing
        }
        
        return structured_context
    
    def _extract_threat_model_summary(self, threat_model_data):
        """Extract and format threat model summary"""
        if not threat_model_data:
            return "No threat model data available."
            
        # Handle different possible structures
        if isinstance(threat_model_data, dict):
            if "raw_response" in threat_model_data and "threat_model" in threat_model_data["raw_response"]:
                threats = threat_model_data["raw_response"]["threat_model"]
            elif "threat_model" in threat_model_data:
                threats = threat_model_data["threat_model"]
            else:
                threats = []
                
            # Format threats summary
            if threats:
                summary = "Threat Model Summary:\n"
                for i, threat in enumerate(threats, 1):
                    threat_type = threat.get("type", "Unknown")
                    description = threat.get("description", "No description")
                    summary += f"{i}. {threat_type}: {description}\n"
                return summary
        
        # Fallback to JSON string if structure is unexpected
        return json.dumps(threat_model_data, indent=2)
    
    def _extract_dread_summary(self, dread_data):
        """Extract and format DREAD assessment summary"""
        if not dread_data:
            return "No DREAD assessment data available."
            
        # Try to extract the table data
        table_data = []
        if isinstance(dread_data, dict):
            if "table" in dread_data:
                table_data = dread_data["table"]
            elif "raw_response" in dread_data and "table" in dread_data["raw_response"]:
                table_data = dread_data["raw_response"]["table"]
            elif "Risk Assessment" in dread_data:
                table_data = dread_data["Risk Assessment"]
                # Calculate risk scores for each item
                for item in table_data:
                    if all(key in item for key in ["Damage Potential", "Reproducibility", "Exploitability", "Affected Users", "Discoverability"]):
                        # Calculate average of all DREAD metrics
                        risk_score = (
                            float(item["Damage Potential"]) + 
                            float(item["Reproducibility"]) + 
                            float(item["Exploitability"]) + 
                            float(item["Affected Users"]) + 
                            float(item["Discoverability"])
                        ) / 5.0
                        item["Risk Score"] = round(risk_score, 2)
        
        # Format DREAD summary
        if table_data:
            # Sort by risk score if available
            try:
                table_data = sorted(table_data, key=lambda x: float(x.get("Risk Score", 0)), reverse=True)
            except (ValueError, TypeError):
                pass
                
            summary = "DREAD Assessment Summary (Top Threats by Risk Score):\n"
            for i, item in enumerate(table_data[:5], 1):  # Show top 5
                threat_type = item.get("Threat Type", "Unknown")
                scenario = item.get("Scenario", "No scenario")
                risk_score = item.get("Risk Score", "N/A")
                summary += f"{i}. {threat_type} (Risk Score: {risk_score}): {scenario}\n"
            return summary
        
        # Fallback to JSON string if structure is unexpected
        return json.dumps(dread_data, indent=2)
    
    def _extract_mitigation_summary(self, mitigation_data):
        """Extract and format mitigation summary"""
        if not mitigation_data:
            return "No mitigation data available."
            
        # Try to extract mitigations
        mitigations = []
        if isinstance(mitigation_data, dict):
            if "mitigations" in mitigation_data:
                mitigations = mitigation_data["mitigations"]
            elif "raw_response" in mitigation_data and "mitigations" in mitigation_data["raw_response"]:
                mitigations = mitigation_data["raw_response"]["mitigations"]
        
        # Format mitigations summary
        if mitigations:
            summary = "Mitigation Strategies Summary:\n"
            for i, item in enumerate(mitigations[:5], 1):  # Show top 5
                threat = item.get("threat", "Unknown threat")
                strategy = item.get("mitigation", "No strategy")
                summary += f"{i}. For {threat}: {strategy}\n"
            return summary
        
        # Fallback to JSON string if structure is unexpected
        return json.dumps(mitigation_data, indent=2)
    
    def _extract_attack_tree_summary(self, attack_tree_data):
        """Extract and format attack tree summary"""
        if not attack_tree_data:
            return "No attack tree data available."
            
        # Try to extract nodes
        nodes = []
        if isinstance(attack_tree_data, dict):
            if "nodes" in attack_tree_data:
                nodes = attack_tree_data["nodes"]
            elif "attack_tree" in attack_tree_data and "nodes" in attack_tree_data["attack_tree"]:
                nodes = attack_tree_data["attack_tree"]["nodes"]
        
        # Format attack tree summary
        if nodes:
            # Find root nodes (goals)
            goals = [node for node in nodes if node.get("type") == "goal"]
            
            summary = "Attack Tree Summary:\n"
            for i, goal in enumerate(goals[:3], 1):  # Show top 3 goals
                label = goal.get("label", "Unknown goal")
                summary += f"{i}. Attack Goal: {label}\n"
                
                # Find direct children
                goal_id = goal.get("id")
                if goal_id:
                    children = [node for node in nodes if node.get("parent") == goal_id]
                    for j, child in enumerate(children[:3], 1):  # Show top 3 children
                        child_label = child.get("label", "Unknown step")
                        summary += f"   {i}.{j} {child_label}\n"
            
            return summary
        
        # Fallback to JSON string if structure is unexpected
        return json.dumps(attack_tree_data, indent=2)

    def chat_about_report(self, assessment_id, user_query):
        try:
            # Get conversation history for this assessment
            conversation_history = self._get_conversation_history(assessment_id)
            
            # Load or refresh context if needed
            if assessment_id not in self.context:
                self.context[assessment_id] = self._load_context(assessment_id)
            
            # Format conversation history
            history_str = ""
            if conversation_history:
                history_str = "\n".join([
                    f"User: {msg['content']}" if msg['role'] == 'user' else f"Assistant: {msg['content']}"
                    for msg in conversation_history[-self.MAX_HISTORY_MESSAGES:]
                ])
                logging.info(f'Using chat history with {len(conversation_history)} messages')
            
            # Process query with context and conversation history
            response = self._process_query_with_context(
                user_query, 
                self.context[assessment_id], 
                history_str,
                assessment_id
            )
            
            if not isinstance(response, dict) or 'Result' not in response:
                logging.error(f'Invalid response format: {response}')
                response = {"Result": "Sorry, I encountered an error processing your request. Please try again."}
            
            # Add to conversation history
            self._add_to_conversation_history(assessment_id, "user", user_query)
            self._add_to_conversation_history(assessment_id, "assistant", response.get("Result", ""))
            
            return response
            
        except Exception as e:
            logging.error(f'Error in chat_about_report: {str(e)}')
            return {"Result": f"Sorry, I encountered an error: {str(e)}"}

    def _process_query_with_context(self, user_query, context, history_str, assessment_id=None):
        """Process user query with comprehensive context and conversation history"""
        try:
            # Check for special queries that need specific handling
            lower_query = user_query.lower()
            
            # Handle special cases for generating new analyses
            if assessment_id:
                threat_model_data = context.get("raw_data", {}).get("threat_model")
                if threat_model_data:
                    if "generate" in lower_query and ("dread" in lower_query or "risk assessment" in lower_query):
                        result = self.dread_handler.generate_dread_assessment(threat_model_data)
                        if result:
                            self.storage_handler.save_dread_assessment(assessment_id, result['raw_response'])
                            # Update context with new data
                            if assessment_id in self.context:
                                self.context[assessment_id] = self._load_context(assessment_id)
                            return {"Result": "I've generated a new DREAD assessment for you. Here's a summary of the top threats by risk score:\n\n" + 
                                   self._extract_dread_summary(result['raw_response'])}
                    
                    elif "generate" in lower_query and "mitigation" in lower_query:
                        result = self.mitigation_handler.generate_mitigations(threat_model_data)
                        if result:
                            self.storage_handler.save_mitigation_result(assessment_id, result)
                            # Update context with new data
                            if assessment_id in self.context:
                                self.context[assessment_id] = self._load_context(assessment_id)
                            return {"Result": "I've generated new mitigation strategies for you. Here's a summary:\n\n" + 
                                   self._extract_mitigation_summary(result)}
                    
                    elif "generate" in lower_query and "attack tree" in lower_query:
                        result = self.attack_tree_handler.generate_attack_tree(threat_model_data)
                        if result:
                            self.storage_handler.save_attack_tree(assessment_id, result['attack_tree'])
                            # Update context with new data
                            if assessment_id in self.context:
                                self.context[assessment_id] = self._load_context(assessment_id)
                            return {"Result": "I've generated a new attack tree for you. Here's a summary of the key attack paths:\n\n" + 
                                   self._extract_attack_tree_summary(result['attack_tree'])}
            
            # Create a structured context string for the prompt
            context_str = f"""
            ### Threat Model Summary:
            {context.get('threat_model', 'No threat model available.')}
            
            ### DREAD Assessment Summary:
            {context.get('dread_assessment', 'No DREAD assessment available.')}
            
            ### Mitigations Summary:
            {context.get('mitigations', 'No mitigations available.')}
            
            ### Attack Tree Summary:
            {context.get('attack_tree', 'No attack tree available.')}
            
            ### Additional Context:
            {context.get('additional_context', 'No additional context available.')}
            """
            
            # Truncate if needed
            context_str = self._truncate_context(context_str)
            
            # Add conversation history if available
            if history_str:
                context_str += f"\n\n### Previous Conversation:\n{history_str}"
            
            # Get the chat prompt from prompts.json or use default if not available
            chat_prompt = self.prompts.get('chat', {})
            
            if chat_prompt:
                # Use the prompt from prompts.json
                system_context = chat_prompt.get('system_context', "You are a threat modelling security expert. Answer questions in a conversational manner based on the provided context. Never return raw markdown tables or JSON directly - always provide natural language responses.")
                task = chat_prompt.get('task', "Answer the user's questions based on the given context.")
                
                # Format instructions as a numbered list if it's an array
                instructions = chat_prompt.get('instructions', [])
                if isinstance(instructions, list):
                    instructions_text = "\n".join([f"{i+1}. {instruction}" for i, instruction in enumerate(instructions)])
                else:
                    instructions_text = instructions
                
                # Construct the prompt
                prompt = f"""
                {task}
                
                ### Context:
                {context_str}

                ### User Question:
                {user_query}

                ### Instructions:
                {instructions_text}
                """
                
                logging.info('Using chat prompt from prompts.json')
            else:
                # Fall back to the hardcoded prompt if not found in prompts.json
                prompt = f"""
                You are an AI security expert. Answer the user's questions based on the given context.
                
                ### Context:
                {context_str}

                ### User Question:
                {user_query}

                ### Instructions:
                1. Provide a detailed, informative response to the user's question
                2. Base your response only on the information in the context
                3. Format your response as natural, conversational text
                4. Do not respond with raw tables or JSON - always provide natural language responses
                5. Maintain continuity with previous conversation
                6. Consider DREAD for risk assessment and deciding the severity of a issue. If asked about top issues or most important, consider dread to answer.Make sure to include all the Threats in DREAD before making a decision.
                """
                
                logging.warning('Chat prompt not found in prompts.json, using default prompt')
                system_context = "You are a threat modelling security expert. Answer questions in a conversational manner based on the provided context. Never return raw markdown tables or JSON directly - always provide natural language responses."
            
            response = self.client.chat.completions.create(
                model=self.openai_handler.model,
                messages=[
                    {"role": "system", "content": system_context},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=1000
            )
            
            # Get the response content
            response_text = response.choices[0].message.content.strip()
            
            # Wrap in Result format
            return {"Result": response_text}
            
        except Exception as e:
            logging.error(f'Error in _process_query_with_context: {str(e)}')
            return {"Result": f"⚠️ Error processing your query: {str(e)}"}
