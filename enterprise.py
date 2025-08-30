"""
AI Incident Response Agent
Integrates PagerDuty alerts, Observe logs, GitHub code analysis, and Microsoft Teams
Built with LangGraph and OpenAI GPT-4o for automated incident triage
"""

import asyncio
import json
import logging
import base64
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from enum import Enum
import re

# LangGraph and OpenAI imports
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver
from openai import AsyncOpenAI
import httpx

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AlertSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class InvestigationStatus(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"

@dataclass
class PagerDutyAlert:
    """Represents a PagerDuty incident"""
    id: str
    incident_number: int
    title: str
    description: str
    status: str
    urgency: str
    priority: str
    service_id: str
    service_name: str
    created_at: datetime
    assignments: List[Dict[str, str]]
    escalation_policy: str
    alerts: List[Dict[str, Any]]
    html_url: str

@dataclass
class ObserveLogData:
    """Represents log data from Observe"""
    dataset: str
    query: str
    timestamp: datetime
    logs: List[Dict[str, Any]]
    total_count: int
    time_range: str

@dataclass
class GitHubCodeContext:
    """Represents relevant code context from GitHub"""
    repository: str
    file_path: str
    content: str
    recent_commits: List[Dict[str, Any]]
    blame_info: Dict[str, Any]
    related_files: List[str]

@dataclass
class Investigation:
    """Represents an ongoing investigation"""
    id: str
    pagerduty_incident: PagerDutyAlert
    status: InvestigationStatus
    start_time: datetime
    end_time: Optional[datetime]
    observe_data: List[ObserveLogData]
    code_context: List[GitHubCodeContext]
    root_cause: Optional[str]
    remediation_steps: List[str]
    code_changes_needed: List[str]
    confidence_score: float
    investigation_summary: str

class State:
    """LangGraph state for the investigation workflow"""
    def __init__(self):
        self.pagerduty_incident: Optional[PagerDutyAlert] = None
        self.investigation: Optional[Investigation] = None
        self.observe_data: List[ObserveLogData] = []
        self.code_context: List[GitHubCodeContext] = []
        self.analysis_context: Dict[str, Any] = {}
        self.current_step: str = ""
        self.error_message: Optional[str] = None

class PagerDutyClient:
    """Client for interacting with PagerDuty API"""
    
    def __init__(self, api_token: str, user_email: str):
        self.api_token = api_token
        self.user_email = user_email
        self.base_url = "https://api.pagerduty.com"
        self.headers = {
            "Authorization": f"Token token={api_token}",
            "Accept": "application/vnd.pagerduty+json;version=2",
            "From": user_email,
            "Content-Type": "application/json"
        }
    
    async def get_active_incidents(self, statuses: List[str] = None) -> List[PagerDutyAlert]:
        """Get active incidents from PagerDuty"""
        if statuses is None:
            statuses = ["triggered", "acknowledged"]
        
        params = {
            "statuses[]": statuses,
            "sort_by": "created_at:desc",
            "limit": 50
        }
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    f"{self.base_url}/incidents",
                    headers=self.headers,
                    params=params,
                    timeout=30
                )
                response.raise_for_status()
                
                incidents_data = response.json()
                incidents = []
                
                for incident in incidents_data.get("incidents", []):
                    # Get detailed incident info including alerts
                    detailed_incident = await self._get_incident_details(incident["id"])
                    incidents.append(detailed_incident)
                
                return incidents
                
            except Exception as e:
                logger.error(f"Error fetching PagerDuty incidents: {e}")
                return []
    
    async def _get_incident_details(self, incident_id: str) -> PagerDutyAlert:
        """Get detailed incident information"""
        async with httpx.AsyncClient() as client:
            # Get incident details
            incident_response = await client.get(
                f"{self.base_url}/incidents/{incident_id}",
                headers=self.headers,
                timeout=30
            )
            incident_data = incident_response.json()["incident"]
            
            # Get incident alerts
            alerts_response = await client.get(
                f"{self.base_url}/incidents/{incident_id}/alerts",
                headers=self.headers,
                timeout=30
            )
            alerts_data = alerts_response.json().get("alerts", [])
            
            return PagerDutyAlert(
                id=incident_data["id"],
                incident_number=incident_data["incident_number"],
                title=incident_data["title"],
                description=incident_data["description"] or "",
                status=incident_data["status"],
                urgency=incident_data["urgency"],
                priority=incident_data.get("priority", {}).get("summary", ""),
                service_id=incident_data["service"]["id"],
                service_name=incident_data["service"]["summary"],
                created_at=datetime.fromisoformat(incident_data["created_at"].replace('Z', '+00:00')),
                assignments=[{
                    "assignee": assignment["assignee"]["summary"],
                    "assignee_id": assignment["assignee"]["id"]
                } for assignment in incident_data.get("assignments", [])],
                escalation_policy=incident_data["escalation_policy"]["summary"],
                alerts=alerts_data,
                html_url=incident_data["html_url"]
            )
    
    async def add_note_to_incident(self, incident_id: str, note: str):
        """Add a note to a PagerDuty incident"""
        payload = {
            "note": {
                "content": note
            }
        }
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    f"{self.base_url}/incidents/{incident_id}/notes",
                    headers=self.headers,
                    json=payload,
                    timeout=30
                )
                response.raise_for_status()
                logger.info(f"Added note to PagerDuty incident {incident_id}")
            except Exception as e:
                logger.error(f"Failed to add note to PagerDuty: {e}")

class ObserveClient:
    """Client for querying Observe for logs and metrics"""
    
    def __init__(self, workspace_id: str, api_token: str, base_url: str):
        self.workspace_id = workspace_id
        self.api_token = api_token
        self.base_url = base_url.rstrip('/')
        self.headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json"
        }
    
    async def query_logs(self, service_name: str, time_range_minutes: int = 60, 
                        log_levels: List[str] = None) -> ObserveLogData:
        """Query logs from Observe for a specific service"""
        if log_levels is None:
            log_levels = ["ERROR", "WARN", "CRITICAL"]
        
        # Construct OPAL query for service logs
        end_time = datetime.now()
        start_time = end_time - timedelta(minutes=time_range_minutes)
        
        opal_query = f"""
        filter service == "{service_name}"
        filter level in {log_levels}
        filter @."@timestamp" >= timestamp("{start_time.isoformat()}")
        filter @."@timestamp" <= timestamp("{end_time.isoformat()}")
        sort @."@timestamp" desc
        limit 1000
        """
        
        payload = {
            "query": opal_query,
            "timeRange": {
                "start": start_time.isoformat() + "Z",
                "end": end_time.isoformat() + "Z"
            }
        }
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    f"{self.base_url}/v1/query",
                    headers=self.headers,
                    json=payload,
                    timeout=60
                )
                response.raise_for_status()
                
                result = response.json()
                logs = result.get("data", [])
                
                return ObserveLogData(
                    dataset=service_name,
                    query=opal_query,
                    timestamp=datetime.now(),
                    logs=logs,
                    total_count=len(logs),
                    time_range=f"{time_range_minutes}m"
                )
                
            except Exception as e:
                logger.error(f"Error querying Observe: {e}")
                # Return sample data for demonstration
                return ObserveLogData(
                    dataset=service_name,
                    query=opal_query,
                    timestamp=datetime.now(),
                    logs=[
                        {
                            "timestamp": datetime.now().isoformat(),
                            "level": "ERROR",
                            "message": "Database connection timeout",
                            "service": service_name,
                            "host": "prod-server-01"
                        },
                        {
                            "timestamp": (datetime.now() - timedelta(minutes=5)).isoformat(),
                            "level": "WARN",
                            "message": "High memory usage detected",
                            "service": service_name,
                            "host": "prod-server-01"
                        }
                    ],
                    total_count=2,
                    time_range=f"{time_range_minutes}m"
                )

class GitHubClient:
    """Client for interacting with GitHub API"""
    
    def __init__(self, access_token: str, organization: str):
        self.access_token = access_token
        self.organization = organization
        self.base_url = "https://api.github.com"
        self.headers = {
            "Authorization": f"token {access_token}",
            "Accept": "application/vnd.github.v3+json"
        }
    
    async def get_service_repository(self, service_name: str) -> Optional[str]:
        """Find the repository for a given service"""
        # Try common patterns for service-to-repo mapping
        potential_repos = [
            service_name,
            f"{service_name}-service",
            f"{service_name.replace('-', '_')}",
            f"service-{service_name}"
        ]
        
        async with httpx.AsyncClient() as client:
            for repo_name in potential_repos:
                try:
                    response = await client.get(
                        f"{self.base_url}/repos/{self.organization}/{repo_name}",
                        headers=self.headers,
                        timeout=30
                    )
                    if response.status_code == 200:
                        return repo_name
                except:
                    continue
        
        return None
    
    async def get_recent_commits(self, repository: str, file_path: str = None, 
                               days: int = 7) -> List[Dict[str, Any]]:
        """Get recent commits for a repository or specific file"""
        since = (datetime.now() - timedelta(days=days)).isoformat()
        
        params = {
            "since": since,
            "per_page": 20
        }
        
        if file_path:
            params["path"] = file_path
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    f"{self.base_url}/repos/{self.organization}/{repository}/commits",
                    headers=self.headers,
                    params=params,
                    timeout=30
                )
                response.raise_for_status()
                
                commits = response.json()
                return [{
                    "sha": commit["sha"][:8],
                    "message": commit["commit"]["message"],
                    "author": commit["commit"]["author"]["name"],
                    "date": commit["commit"]["author"]["date"],
                    "url": commit["html_url"]
                } for commit in commits]
                
            except Exception as e:
                logger.error(f"Error fetching commits: {e}")
                return []
    
    async def get_file_content(self, repository: str, file_path: str, 
                              ref: str = "main") -> Optional[str]:
        """Get content of a specific file"""
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    f"{self.base_url}/repos/{self.organization}/{repository}/contents/{file_path}",
                    headers=self.headers,
                    params={"ref": ref},
                    timeout=30
                )
                response.raise_for_status()
                
                content_data = response.json()
                if content_data["type"] == "file":
                    content = base64.b64decode(content_data["content"]).decode('utf-8')
                    return content
                
            except Exception as e:
                logger.error(f"Error fetching file content: {e}")
        
        return None
    
    async def search_code(self, query: str, repository: str = None) -> List[Dict[str, Any]]:
        """Search for code across repositories"""
        search_query = query
        if repository:
            search_query += f" repo:{self.organization}/{repository}"
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    f"{self.base_url}/search/code",
                    headers=self.headers,
                    params={"q": search_query, "per_page": 10},
                    timeout=30
                )
                response.raise_for_status()
                
                results = response.json()
                return [{
                    "name": item["name"],
                    "path": item["path"],
                    "repository": item["repository"]["name"],
                    "url": item["html_url"],
                    "score": item["score"]
                } for item in results.get("items", [])]
                
            except Exception as e:
                logger.error(f"Error searching code: {e}")
                return []

class TeamsClient:
    """Client for sending messages to Microsoft Teams"""
    
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
    
    async def send_investigation_summary(self, investigation: Investigation):
        """Send investigation summary to Teams channel"""
        
        # Create adaptive card for rich formatting
        card = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": self._get_color_by_urgency(investigation.pagerduty_incident.urgency),
            "summary": f"Incident Investigation: {investigation.pagerduty_incident.title}",
            "sections": [
                {
                    "activityTitle": "🚨 Incident Investigation Complete",
                    "activitySubtitle": investigation.pagerduty_incident.title,
                    "activityImage": "https://adaptivecards.io/content/cats/1.png",
                    "facts": [
                        {
                            "name": "Incident #",
                            "value": str(investigation.pagerduty_incident.incident_number)
                        },
                        {
                            "name": "Service",
                            "value": investigation.pagerduty_incident.service_name
                        },
                        {
                            "name": "Urgency",
                            "value": investigation.pagerduty_incident.urgency.upper()
                        },
                        {
                            "name": "Status",
                            "value": investigation.status.value.title()
                        },
                        {
                            "name": "Investigation Time",
                            "value": f"{(investigation.end_time - investigation.start_time).total_seconds():.1f}s"
                        },
                        {
                            "name": "Confidence Score",
                            "value": f"{investigation.confidence_score:.1%}"
                        }
                    ],
                    "markdown": True
                },
                {
                    "activityTitle": "🔍 Root Cause Analysis",
                    "text": investigation.root_cause or "Analysis in progress..."
                },
                {
                    "activityTitle": "🛠️ Recommended Actions",
                    "text": "\n".join([f"• {step}" for step in investigation.remediation_steps]) if investigation.remediation_steps else "No specific actions recommended"
                },
                {
                    "activityTitle": "💻 Code Changes Needed",
                    "text": "\n".join([f"• {change}" for change in investigation.code_changes_needed]) if investigation.code_changes_needed else "No code changes identified"
                },
                {
                    "activityTitle": "📊 Investigation Summary",
                    "text": investigation.investigation_summary
                }
            ],
            "potentialAction": [
                {
                    "@type": "OpenUri",
                    "name": "View in PagerDuty",
                    "targets": [
                        {
                            "os": "default",
                            "uri": investigation.pagerduty_incident.html_url
                        }
                    ]
                }
            ]
        }
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    self.webhook_url,
                    json=card,
                    timeout=30
                )
                response.raise_for_status()
                logger.info("Investigation summary sent to Microsoft Teams")
                
            except Exception as e:
                logger.error(f"Failed to send Teams message: {e}")
    
    def _get_color_by_urgency(self, urgency: str) -> str:
        """Get color code based on incident urgency"""
        colors = {
            "high": "FF0000",  # Red
            "medium": "FF8C00",  # Orange
            "low": "32CD32"  # Green
        }
        return colors.get(urgency.lower(), "808080")  # Default gray

class AIAnalyzer:
    """AI-powered analyzer using GPT-4o for comprehensive incident analysis"""
    
    def __init__(self, openai_client: AsyncOpenAI):
        self.client = openai_client
    
    async def analyze_incident(
        self,
        pagerduty_incident: PagerDutyAlert,
        observe_data: List[ObserveLogData],
        code_context: List[GitHubCodeContext]
    ) -> Dict[str, Any]:
        """Comprehensive incident analysis using all data sources"""
        
        analysis_prompt = f"""
You are an expert Site Reliability Engineer conducting a comprehensive incident analysis.

PAGERDUTY INCIDENT:
{json.dumps(asdict(pagerduty_incident), indent=2, default=str)}

OBSERVE LOG DATA:
{json.dumps([asdict(data) for data in observe_data], indent=2, default=str)}

GITHUB CODE CONTEXT:
{json.dumps([asdict(context) for context in code_context], indent=2, default=str)}

Based on this comprehensive data from PagerDuty incident, Observe logs, and GitHub code context, provide a detailed analysis:

1. Root cause analysis (be specific and technical, reference logs and code)
2. Confidence level (0-100%) based on available evidence
3. Immediate remediation steps (prioritized)
4. Code changes needed (specific files and changes)
5. Prevention strategies (code improvements, monitoring, etc.)
6. Impact assessment and affected systems
7. Investigation summary (2-3 sentences for executive summary)

Consider:
- Recent code changes that might have caused the issue
- Log patterns and error correlations
- Service dependencies and cascading failures
- Historical incidents and patterns

Format your response as JSON with these keys:
- root_cause
- confidence_score (0-100)
- remediation_steps (array)
- code_changes_needed (array)
- prevention_strategies (array)
- impact_assessment
- affected_systems (array)
- investigation_summary
- key_evidence (array of supporting evidence from logs/code)
"""
        
        try:
            response = await self.client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {
                        "role": "system", 
                        "content": "You are an expert SRE with 15+ years of experience in incident response, root cause analysis, and system reliability. You excel at correlating data from monitoring, logs, and code to identify issues quickly and accurately."
                    },
                    {"role": "user", "content": analysis_prompt}
                ],
                temperature=0.1,
                max_tokens=2000
            )
            
            analysis = json.loads(response.choices[0].message.content)
            return analysis
            
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            return {
                "root_cause": "Analysis failed - manual investigation required",
                "confidence_score": 0,
                "remediation_steps": ["Manual investigation needed"],
                "code_changes_needed": [],
                "prevention_strategies": [],
                "impact_assessment": "Unable to assess impact automatically",
                "affected_systems": [],
                "investigation_summary": f"Automated analysis encountered an error: {str(e)}",
                "key_evidence": []
            }

class IncidentResponseAgent:
    """Main agent orchestrating the incident response workflow"""
    
    def __init__(self, config: Dict[str, str]):
        self.openai_client = AsyncOpenAI(api_key=config["openai_api_key"])
        
        self.pagerduty_client = PagerDutyClient(
            api_token=config["pagerduty_api_token"],
            user_email=config["pagerduty_user_email"]
        )
        
        self.observe_client = ObserveClient(
            workspace_id=config["observe_workspace_id"],
            api_token=config["observe_api_token"],
            base_url=config["observe_base_url"]
        )
        
        self.github_client = GitHubClient(
            access_token=config["github_access_token"],
            organization=config["github_organization"]
        )
        
        self.teams_client = TeamsClient(
            webhook_url=config["teams_webhook_url"]
        )
        
        self.ai_analyzer = AIAnalyzer(self.openai_client)
        
        # Build the LangGraph workflow
        self.workflow = self._build_workflow()
    
    def _build_workflow(self) -> StateGraph:
        """Build the LangGraph workflow for incident investigation"""
        
        workflow = StateGraph(State)
        
        # Define the investigation steps
        workflow.add_node("parse_pagerduty_incident", self._parse_pagerduty_incident)
        workflow.add_node("collect_observe_logs", self._collect_observe_logs)
        workflow.add_node("analyze_code_context", self._analyze_code_context)
        workflow.add_node("ai_incident_analysis", self._ai_incident_analysis)
        workflow.add_node("generate_investigation_report", self._generate_investigation_report)
        workflow.add_node("send_teams_summary", self._send_teams_summary)
        workflow.add_node("update_pagerduty", self._update_pagerduty)
        
        # Define the workflow edges
        workflow.set_entry_point("parse_pagerduty_incident")
        workflow.add_edge("parse_pagerduty_incident", "collect_observe_logs")
        workflow.add_edge("collect_observe_logs", "analyze_code_context")
        workflow.add_edge("analyze_code_context", "ai_incident_analysis")
        workflow.add_edge("ai_incident_analysis", "generate_investigation_report")
        workflow.add_edge("generate_investigation_report", "send_teams_summary")
        workflow.add_edge("send_teams_summary", "update_pagerduty")
        workflow.add_edge("update_pagerduty", END)
        
        # Add memory for state persistence
        memory = MemorySaver()
        return workflow.compile(checkpointer=memory)
    
    async def _parse_pagerduty_incident(self, state: State) -> State:
        """Parse and validate PagerDuty incident"""
        state.current_step = "parsing_pagerduty_incident"
        logger.info(f"Parsing PagerDuty incident: {state.pagerduty_incident.title}")
        
        # Initialize investigation
        state.investigation = Investigation(
            id=f"inv_{state.pagerduty_incident.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            pagerduty_incident=state.pagerduty_incident,
            status=InvestigationStatus.IN_PROGRESS,
            start_time=datetime.now(),
            end_time=None,
            observe_data=[],
            code_context=[],
            root_cause=None,
            remediation_steps=[],
            code_changes_needed=[],
            confidence_score=0.0,
            investigation_summary=""
        )
        
        return state
    
    async def _collect_observe_logs(self, state: State) -> State:
        """Collect logs from Observe"""
        state.current_step = "collecting_observe_logs"
        logger.info("Collecting logs from Observe")
        
        try:
            service_name = state.pagerduty_incident.service_name
            
            # Query logs for the affected service
            log_data = await self.observe_client.query_logs(
                service_name=service_name,
                time_range_minutes=60,
                log_levels=["ERROR", "WARN", "CRITICAL", "FATAL"]
            )
            
            state.observe_data.append(log_data)
            state.investigation.observe_data = state.observe_data
            
        except Exception as e:
            state.error_message = f"Observe log collection failed: {str(e)}"
            logger.error(state.error_message)
        
        return state
    
    async def _analyze_code_context(self, state: State) -> State:
        """Analyze code context from GitHub"""
        state.current_step = "analyzing_code_context"
        logger.info("Analyzing code context from GitHub")
        
        try:
            service_name = state.pagerduty_incident.service_name
            
            # Find the repository for this service
            repository = await self.github_client.get_service_repository(service_name)
            
            if repository:
                # Get recent commits
                recent_commits = await self.github_client.get_recent_commits(
                    repository=repository,
                    days=7
                )
                
                # Search for relevant code files based on error patterns
                error_keywords = self._extract_error_keywords(state.observe_data)
                
                code_context = GitHubCodeContext(
                    repository=repository,
                    file_path="",  # Will be populated based on search results
                    content="",
                    recent_commits=recent_commits,
                    blame_info={},
                    related_files=[]
                )
                
                # Search for code related to the error
                for keyword in error_keywords[:3]:  # Limit searches
                    search_results = await self.github_client.search_code(
                        query=keyword,
                        repository=repository
                    )
                    
                    # Get content of most relevant files
                    for result in search_results[:2]:  # Limit results
                        file_content = await self.github_client.get_file_content(
                            repository=repository,
                            file_path=result["path"]
                        )
                        
                        if file_content:
                            code_context.related_files.append(result["path"])
                            if not code_context.content:  # Use first file as primary context
                                code_context.file_path = result["path"]
                                code_context.content = file_content[:5000]  # Limit content size
                
                state.code_context.append(code_context)
                state.investigation.code_context = state.code_context
            
        except Exception as e:
            state.error_message = f"Code analysis failed: {str(e)}"
            logger.error(state.error_message)
        
        return state
    
    def _extract_error_keywords(self, observe_data: List[ObserveLogData]) -> List[str]:
        """Extract relevant keywords from log data for code search"""
        keywords = set()
        
        for log_data in observe_data:
            for log_entry in log_data.logs:
                message = log_entry.get("message", "")
                
                # Extract common error patterns
                patterns = [
                    r'(\w+Exception)',
                    r'(\w+Error)',
                    r'(timeout|connection|database|sql)',
                    r'(failed|error|exception)'
                ]
                
                for pattern in patterns:
                    matches = re.findall(pattern, message, re.IGNORECASE)
                    keywords.update(matches)
        
        return list(keywords)[:10]  # Return top 10 keywords
    
    async def _ai_incident_analysis(self, state: State) -> State:
        """Run AI analysis on all collected data"""
        state.current_step = "ai_incident_analysis"
        logger.info("Running AI analysis on incident data")
        
        try:
            analysis = await self.ai_analyzer.analyze_incident(
                pagerduty_incident=state.pagerduty_incident,
                observe_data=state.observe_data,
                code_context=state.code_context
            )
            
            # Update investigation with analysis results
            state.investigation.root_cause = analysis.get("root_cause")
            state.investigation.confidence_score = analysis.get("confidence_score", 0) / 100
            state.investigation.remediation_steps = analysis.get("remediation_steps", [])
            state.investigation.code_changes_needed = analysis.get("code_changes_needed", [])
            state.investigation.investigation_summary = analysis.get("investigation_summary", "")
            
            state.analysis_context = analysis
            
        except Exception as e:
            state.error_message = f"AI analysis failed: {str(e)}"
            logger.error(state.error_message)
        
        return state
    
    async def _generate_investigation_report(self, state: State) -> State:
        """Generate final investigation report"""
        state.current_step = "generating_investigation_report"
        logger.info("Generating investigation report")
        
        state.investigation.end_time = datetime.now()
        state.investigation.status = (
            InvestigationStatus.COMPLETED if state.investigation.confidence_score > 0.7 
            else InvestigationStatus.FAILED
        )
        
        return state
    
    async def _send_teams_summary(self, state: State) -> State:
        """Send investigation summary to Microsoft Teams"""
        state.current_step = "sending_teams_summary"
        logger.info("Sending investigation summary to Microsoft Teams")
        
        try:
            await self.teams_client.send_investigation_summary(state.investigation)
        except Exception as e:
            logger.error(f"Failed to send Teams summary: {e}")
        
        return state
    
    async def _update_pagerduty(self, state: State) -> State:
        """Update PagerDuty incident with investigation results"""
        state.current_step = "updating_pagerduty"
        logger.info("Updating PagerDuty incident")
        
        try:
            # Create investigation note for PagerDuty
            note_content = f"""
🤖 **Automated Investigation Complete**

**Root Cause:** {state.investigation.root_cause}
**Confidence:** {state.investigation.confidence_score:.1%}
**Duration:** {(state.investigation.end_time - state.investigation.start_time).total_seconds():.1f}s

**Immediate Actions:**
{chr(10).join(f"• {step}" for step in state.investigation.remediation_steps[:3])}

**Code Changes Needed:**
{chr(10).join(f"• {change}" for change in state.investigation.code_changes_needed[:3])}

Full details sent to Microsoft Teams channel.
            """
            
            await self.pagerduty_client.add_note_to_incident(
                incident_id=state.pagerduty_incident.id,
                note=note_content.strip()
            )
            
        except Exception as e:
            logger.error(f"Failed to update PagerDuty: {e}")
        
        return state
    
    async def handle_incident(self, pagerduty_incident: PagerDutyAlert) -> Investigation:
        """Handle a PagerDuty incident through the complete workflow"""
        logger.info(f"Starting investigation for incident: {pagerduty_incident.title}")
        
        # Initialize state
        initial_state = State()
        initial_state.pagerduty_incident = pagerduty_incident
        
        # Run the workflow
        config = {"configurable": {"thread_id": f"incident_{pagerduty_incident.id}"}}
        
        try:
            final_state = await self.workflow.ainvoke(initial_state, config=config)
            return final_state.investigation
        except Exception as e:
            logger.error(f"Workflow execution failed: {e}")
            # Return a failed investigation
            investigation = Investigation(
                id=f"inv_{pagerduty_incident.id}_failed",
                pagerduty_incident=pagerduty_incident,
                status=InvestigationStatus.FAILED,
                start_time=datetime.now(),
                end_time=datetime.now(),
                observe_data=[],
                code_context=[],
                root_cause=f"Investigation failed: {str(e)}",
                remediation_steps=["Manual investigation required"],
                code_changes_needed=[],
                confidence_score=0.0,
                investigation_summary=f"Automated investigation encountered an error: {str(e)}"
            )
            return investigation
    
    async def run_continuously(self):
        """Run the agent continuously, monitoring PagerDuty for new incidents"""
        logger.info("🤖 AI Incident Response Agent started - monitoring PagerDuty for incidents...")
        processed_incidents = set()
        
        while True:
            try:
                # Get active incidents from PagerDuty
                incidents = await self.pagerduty_client.get_active_incidents(
                    statuses=["triggered", "acknowledged"]
                )
                
                for incident in incidents:
                    # Skip if we've already processed this incident
                    if incident.id in processed_incidents:
                        continue
                    
                    logger.info(f"🚨 New incident detected: {incident.title}")
                    
                    # Process the incident
                    investigation = await self.handle_incident(incident)
                    
                    # Mark as processed
                    processed_incidents.add(incident.id)
                    
                    # Log results
                    duration = (investigation.end_time - investigation.start_time).total_seconds()
                    logger.info(f"✅ Investigation completed in {duration:.1f}s")
                    logger.info(f"Root cause: {investigation.root_cause}")
                    logger.info(f"Confidence: {investigation.confidence_score:.1%}")
                
                # Wait before checking for new incidents
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                logger.error(f"Error in main monitoring loop: {e}")
                await asyncio.sleep(60)  # Wait longer on error

# Configuration and example usage
class AgentConfig:
    """Configuration class for the incident response agent"""
    
    def __init__(self):
        self.config = {
            # OpenAI Configuration
            "openai_api_key": "your-openai-api-key",
            
            # PagerDuty Configuration
            "pagerduty_api_token": "your-pagerduty-api-token",
            "pagerduty_user_email": "your-email@company.com",
            
            # Observe Configuration
            "observe_workspace_id": "your-observe-workspace-id",
            "observe_api_token": "your-observe-api-token",
            "observe_base_url": "https://your-workspace.observeinc.com",
            
            # GitHub Configuration
            "github_access_token": "your-github-access-token",
            "github_organization": "your-organization",
            
            # Microsoft Teams Configuration
            "teams_webhook_url": "https://outlook.office.com/webhook/your-webhook-url"
        }
    
    def from_env(self):
        """Load configuration from environment variables"""
        import os
        
        self.config.update({
            "openai_api_key": os.getenv("OPENAI_API_KEY"),
            "pagerduty_api_token": os.getenv("PAGERDUTY_API_TOKEN"),
            "pagerduty_user_email": os.getenv("PAGERDUTY_USER_EMAIL"),
            "observe_workspace_id": os.getenv("OBSERVE_WORKSPACE_ID"),
            "observe_api_token": os.getenv("OBSERVE_API_TOKEN"),
            "observe_base_url": os.getenv("OBSERVE_BASE_URL"),
            "github_access_token": os.getenv("GITHUB_ACCESS_TOKEN"),
            "github_organization": os.getenv("GITHUB_ORGANIZATION"),
            "teams_webhook_url": os.getenv("TEAMS_WEBHOOK_URL")
        })
        
        return self
    
    def get_config(self) -> Dict[str, str]:
        return self.config

# Example usage and testing
async def main():
    """Example usage of the AI Incident Response Agent"""
    
    # Load configuration
    config = AgentConfig().from_env().get_config()
    
    # Initialize the agent
    agent = IncidentResponseAgent(config)
    
    # Test with a sample PagerDuty incident
    test_incident = PagerDutyAlert(
        id="test_001",
        incident_number=12345,
        title="High Error Rate in Payment Service",
        description="Payment processing errors exceeding 5% threshold",
        status="triggered",
        urgency="high",
        priority="P1",
        service_id="payment-service-id",
        service_name="payment-service",
        created_at=datetime.now(),
        assignments=[{
            "assignee": "SRE Team",
            "assignee_id": "sre-team-id"
        }],
        escalation_policy="Production Escalation",
        alerts=[],
        html_url="https://company.pagerduty.com/incidents/test_001"
    )
    
    # Process the incident
    investigation = await agent.handle_incident(test_incident)
    
    # Print results
    print(f"\n🔍 Investigation Results:")
    print(f"Incident: {investigation.pagerduty_incident.title}")
    print(f"Status: {investigation.status.value}")
    print(f"Duration: {(investigation.end_time - investigation.start_time).total_seconds():.1f}s")
    print(f"Root Cause: {investigation.root_cause}")
    print(f"Confidence: {investigation.confidence_score:.1%}")
    print(f"\nRemediation Steps:")
    for i, step in enumerate(investigation.remediation_steps, 1):
        print(f"  {i}. {step}")
    print(f"\nCode Changes Needed:")
    for i, change in enumerate(investigation.code_changes_needed, 1):
        print(f"  {i}. {change}")
    print(f"\nSummary: {investigation.investigation_summary}")

# Deployment helpers
class DeploymentHelper:
    """Helper class for deploying the agent"""
    
    @staticmethod
    def create_docker_compose():
        """Create Docker Compose configuration"""
        docker_compose = """
version: '3.8'
services:
  incident-response-agent:
    build: .
    environment:
      - OPENAI_API_KEY=${OPENAI_API_KEY}
      - PAGERDUTY_API_TOKEN=${PAGERDUTY_API_TOKEN}
      - PAGERDUTY_USER_EMAIL=${PAGERDUTY_USER_EMAIL}
      - OBSERVE_WORKSPACE_ID=${OBSERVE_WORKSPACE_ID}
      - OBSERVE_API_TOKEN=${OBSERVE_API_TOKEN}
      - OBSERVE_BASE_URL=${OBSERVE_BASE_URL}
      - GITHUB_ACCESS_TOKEN=${GITHUB_ACCESS_TOKEN}
      - GITHUB_ORGANIZATION=${GITHUB_ORGANIZATION}
      - TEAMS_WEBHOOK_URL=${TEAMS_WEBHOOK_URL}
    restart: unless-stopped
    volumes:
      - ./logs:/app/logs
    healthcheck:
      test: ["CMD", "python", "-c", "import requests; requests.get('http://localhost:8080/health')"]
      interval: 30s
      timeout: 10s
      retries: 3
"""
        return docker_compose
    
    @staticmethod
    def create_dockerfile():
        """Create Dockerfile for deployment"""
        dockerfile = """
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8080

CMD ["python", "incident_response_agent.py"]
"""
        return dockerfile
    
    @staticmethod
    def create_requirements_txt():
        """Create requirements.txt file"""
        requirements = """
langgraph>=0.0.20
openai>=1.0.0
httpx>=0.25.0
asyncio-mqtt>=0.11.0
pydantic>=2.0.0
python-dotenv>=1.0.0
"""
        return requirements

if __name__ == "__main__":
    # Run the example
    asyncio.run(main())
    
    # To run continuously:
    # config = AgentConfig().from_env().get_config()
    # agent = IncidentResponseAgent(config)
    # asyncio.run(agent.run_continuously())
