# Threat Modeling Application Architecture

## High-Level Architecture Diagram

```mermaid
graph TB
    subgraph Frontend["Frontend Layer"]
        UI["Web UI\n(templates/)"]
        style UI fill:#f9f,stroke:#333,stroke-width:2px
    end

    subgraph Core["Core Layer"]
        TM["Threat Modeling Engine\n(core/threat_modeling.py)"]
        AT["Attack Tree Generator\n(core/attack_tree.py)"]
        DR["DREAD Assessment\n(core/dread.py)"]
        MT["Mitigation Handler\n(core/mitigation.py)"]
        BOT["AI Bot Interface\n(core/bot.py)"]
        style TM fill:#90EE90,stroke:#333,stroke-width:2px
        style AT fill:#90EE90,stroke:#333,stroke-width:2px
        style DR fill:#90EE90,stroke:#333,stroke-width:2px
        style MT fill:#90EE90,stroke:#333,stroke-width:2px
        style BOT fill:#90EE90,stroke:#333,stroke-width:2px
    end

    subgraph LLM["LLM Layer"]
        OAI["OpenAI Handler\n(llm/openai_module.py)"]
        style OAI fill:#ADD8E6,stroke:#333,stroke-width:2px
    end

    subgraph RAG["RAG Layer"]
        RH["RAG Handler\n(rag/rag_handler.py)"]
        style RH fill:#FFB6C1,stroke:#333,stroke-width:2px
    end

    subgraph Storage["Storage Layer"]
        ST["Storage Handler\n(utils/storage.py)"]
        Files["File Storage\n(storage/)"]
        style ST fill:#DEB887,stroke:#333,stroke-width:2px
        style Files fill:#DEB887,stroke:#333,stroke-width:2px
    end

    UI --> TM
    UI --> AT
    UI --> DR
    UI --> MT
    UI --> BOT

    TM --> OAI
    AT --> OAI
    DR --> OAI
    MT --> OAI
    BOT --> OAI

    TM --> RH
    AT --> RH
    DR --> RH
    MT --> RH

    RH --> ST
    ST --> Files
```

## Data Flow Diagram

```mermaid
flowchart TD
    subgraph Input["Input Sources"]
        User["User Input"]
        Doc["Document Upload"]
    end

    subgraph Processing["Processing Layer"]
        ThreatModel["Threat Modeling\nEngine"]
        RAG["RAG Processing"]
        LLM["LLM Integration"]
    end

    subgraph Analysis["Analysis Components"]
        AT["Attack Tree\nGeneration"]
        DR["DREAD Risk\nAssessment"]
        MT["Mitigation\nStrategies"]
    end

    subgraph Storage["Storage Layer"]
        JSON["JSON Storage"]
        FS["File System"]
    end

    subgraph Output["Output Layer"]
        Report["Threat Model\nReport"]
        Visual["Visualization"]
    end

    %% Data Flow Connections
    User -->|"Application\nDescription"| ThreatModel
    Doc -->|"Documentation\n& Code"| RAG
    RAG -->|"Processed\nContext"| ThreatModel
    ThreatModel -->|"Threat\nModel"| Analysis
    ThreatModel <-->|"API Calls"| LLM
    
    AT -->|"Attack Tree\nData"| JSON
    DR -->|"Risk Scores"| JSON
    MT -->|"Mitigation\nStrategies"| JSON
    
    JSON -->|"Stored\nResults"| Report
    JSON -->|"Tree\nData"| Visual
    
    Analysis -->|"Analysis\nResults"| FS
    FS -->|"Retrieved\nData"| Report
```

## Component Interaction Diagram

```mermaid
sequenceDiagram
    participant U as User
    participant W as Web UI
    participant T as Threat Model Engine
    participant L as LLM Service
    participant R as RAG Handler
    participant S as Storage

    U->>W: Submit Application Details
    W->>T: Process Request
    T->>R: Get Context
    R->>S: Retrieve Related Data
    S-->>R: Return Context
    R-->>T: Provide Context
    T->>L: Generate Threat Model
    L-->>T: Return Analysis
    T->>S: Store Results
    T-->>W: Return Response
    W-->>U: Display Results

    Note over U,S: Subsequent Analysis Flow
    U->>W: Request Additional Analysis
    W->>T: Process Analysis Request
    T->>S: Get Threat Model
    S-->>T: Return Model
    T->>L: Generate Analysis<br/>(Attack Tree/DREAD/Mitigation)
    L-->>T: Return Analysis
    T->>S: Store Analysis
    T-->>W: Return Results
    W-->>U: Display Analysis
