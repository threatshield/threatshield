import React, { useEffect, useRef } from 'react';
import mermaid from 'mermaid';

interface MermaidDiagramProps {
  content: string;
  onNodeClick?: (nodeId: string) => void;
}

mermaid.initialize({
  startOnLoad: false,
  theme: 'neutral',
  securityLevel: 'loose',
  flowchart: {
    htmlLabels: true,
    curve: 'basis',
  },
  themeVariables: {
    fontFamily: 'system-ui, -apple-system, sans-serif',
    fontSize: '14px',
    primaryColor: '#e6e6e6',
    primaryTextColor: '#333333',
    primaryBorderColor: '#666666',
    lineColor: '#666666',
    secondaryColor: '#f5f5f5',
    tertiaryColor: '#f9f9f9',
  },
});

let diagramCounter = 0;

const MermaidDiagram: React.FC<MermaidDiagramProps> = ({ content, onNodeClick }) => {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!containerRef.current || !content) return;

    const container = containerRef.current;
    const cleanContent = content.replace(/```mermaid|```/g, '').trim();
    const id = `mermaid-diagram-${++diagramCounter}`;

    mermaid.render(id, cleanContent)
      .then(({ svg }) => {
        container.innerHTML = svg;

        if (onNodeClick) {
          container.querySelectorAll('.node').forEach(node => {
            (node as HTMLElement).style.cursor = 'pointer';
            node.addEventListener('click', () => {
              const nodeId = node.id.replace('flowchart-', '').replace(/-\d+$/, '');
              onNodeClick(nodeId);
            });
          });
        }
      })
      .catch((err) => {
        console.error('Mermaid render error:', err);
        container.innerHTML = `
          <div class="p-4 bg-red-50 text-red-700 rounded-md">
            <p class="font-medium text-sm">Error rendering diagram</p>
            <pre class="mt-2 text-xs whitespace-pre-wrap break-all">${cleanContent.slice(0, 500)}</pre>
          </div>
        `;
      });
  }, [content, onNodeClick]);

  return <div ref={containerRef} className="prose prose-indigo max-w-none" />;
};

export default MermaidDiagram;
