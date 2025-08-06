import React, { useEffect, useRef } from 'react';
import mermaid from 'mermaid';

interface MermaidDiagramProps {
  content: string;
}

const MermaidDiagram: React.FC<MermaidDiagramProps> = ({ content }) => {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (containerRef.current) {
      mermaid.initialize({
        startOnLoad: true,
        theme: 'default',
        securityLevel: 'loose',
        flowchart: {
          htmlLabels: true,
          curve: 'basis'
        }
      });

      // Clean the content by removing mermaid code block markers
      const cleanContent = content.replace(/```mermaid|```/g, '').trim();

      // Generate a unique ID for this diagram
      const uniqueId = `mermaid-${Math.random().toString(36).substr(2, 9)}`;
      containerRef.current.innerHTML = `<div class="mermaid" id="${uniqueId}">${cleanContent}</div>`;

      try {
        mermaid.contentLoaded();
      } catch (error) {
        console.error('Error rendering Mermaid diagram:', error);
        containerRef.current.innerHTML = `
          <div class="p-4 bg-red-50 text-red-700 rounded-md">
            <p class="font-medium">Error rendering diagram</p>
            <pre class="mt-2 text-sm">${cleanContent}</pre>
          </div>
        `;
      }
    }
  }, [content]);

  return <div ref={containerRef} className="prose prose-indigo max-w-none" />;
};

export default MermaidDiagram;
