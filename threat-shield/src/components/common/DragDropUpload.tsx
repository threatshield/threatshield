import React, { useState, useRef, useCallback } from 'react';

interface DragDropUploadProps {
  onFilesSelected: (files: FileList) => void;
  onFileRemove?: (index: number) => void;
  accept?: string;
  multiple?: boolean;
  className?: string;
  initialFiles?: FileList | null;
}

const DragDropUpload: React.FC<DragDropUploadProps> = ({
  onFilesSelected,
  onFileRemove,
  accept = "image/*",
  multiple = true,
  className = "",
  initialFiles = null,
}) => {
  const [isDragging, setIsDragging] = useState(false);
  const [fileNames, setFileNames] = useState<string[]>(
    initialFiles ? Array.from(initialFiles).map(file => file.name) : []
  );
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDragEnter = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  }, []);

  const handleDragOver = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    if (!isDragging) {
      setIsDragging(true);
    }
  }, [isDragging]);

  const handleDrop = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const newFileNames = Array.from(e.dataTransfer.files).map(file => file.name);
      setFileNames(prev => [...prev, ...newFileNames]);
      onFilesSelected(e.dataTransfer.files);
      e.dataTransfer.clearData();
    }
  }, [onFilesSelected]);

  const handleFileInputChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      const newFileNames = Array.from(e.target.files).map(file => file.name);
      setFileNames(prev => [...prev, ...newFileNames]);
      onFilesSelected(e.target.files);
    }
  }, [onFilesSelected]);

  const handleButtonClick = useCallback(() => {
    if (fileInputRef.current) {
      fileInputRef.current.click();
    }
  }, []);

  const removeFile = useCallback((index: number) => {
    setFileNames(prev => prev.filter((_, i) => i !== index));
    // Call the onFileRemove callback if provided
    if (onFileRemove) {
      onFileRemove(index);
    }
  }, [onFileRemove]);

  return (
    <div className={`${className}`}>
      <div
        className={`border-2 border-dashed rounded-lg p-8 transition-all duration-300 ${
          isDragging 
            ? 'border-[#0052cc] bg-blue-50/50 shadow-md' 
            : 'border-blue-200 bg-white hover:border-blue-300 hover:bg-blue-50/30'
        }`}
        onDragEnter={handleDragEnter}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
      >
        <div className="flex flex-col items-center justify-center space-y-4">
          <div className={`p-4 rounded-full ${isDragging ? 'bg-blue-100' : 'bg-blue-50'}`}>
            <svg xmlns="http://www.w3.org/2000/svg" className="h-10 w-10 text-[#0052cc]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
            </svg>
          </div>
          
          <div className="text-center">
            <p className="text-lg font-medium text-gray-700">
              {isDragging ? 'Drop files here' : 'Drag & drop files here'}
            </p>
            <p className="text-sm text-gray-500 mt-1">or</p>
          </div>
          
          <button
            type="button"
            onClick={handleButtonClick}
            className="px-6 py-3 bg-[#0052cc] text-white rounded-lg hover:bg-[#0747a6] transition-all duration-300 flex items-center shadow-sm hover:shadow-md hover:scale-105"
          >
            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
            </svg>
            Browse Files
          </button>
          
          <input
            ref={fileInputRef}
            type="file"
            className="hidden"
            accept={accept}
            multiple={multiple}
            onChange={handleFileInputChange}
          />
          
          <p className="text-xs text-gray-500">
            {multiple ? 'Upload one or more files' : 'Upload a file'}
          </p>
        </div>
      </div>
      
      {/* File List */}
      {fileNames.length > 0 && (
        <div className="mt-4 space-y-2">
          <p className="text-sm font-medium text-gray-700">Selected files:</p>
          <ul className="space-y-2">
            {fileNames.map((name, index) => (
              <li key={index} className="flex items-center justify-between bg-blue-50/50 p-3 rounded-lg border border-blue-100">
                <div className="flex items-center">
                  <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-[#0052cc] mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                  </svg>
                  <span className="text-sm text-gray-700 truncate max-w-xs">{name}</span>
                </div>
                <button
                  type="button"
                  onClick={() => removeFile(index)}
                  className="text-red-500 hover:text-red-700"
                >
                  <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
};

export default DragDropUpload;
