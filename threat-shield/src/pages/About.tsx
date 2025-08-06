import React from 'react';

const About: React.FC = () => {
  const teamMembers = [
    {
      name: "Satyam Nagpal",
      role: "Lead Security Engineer at CRED",
      github: "https://github.com/Satyam9927",
      twitter: "https://x.com/satyamnagpal",
      linkedin: "https://in.linkedin.com/in/satyamnagpal"
    },
    {
      name: "Ashwin Shenoi",
      role: "Lead Security Engineer at CRED",
      github: "https://github.com/ashwinshenoi99",
      twitter: "https://x.com/__c3rb3ru5__",
      linkedin: "https://in.linkedin.com/in/ashwinshenoi"
    },
    {
      name: "Sayooj B Kumar",
      role: "Senior Security Engineer at CRED",
      github: "https://github.com/sayoojbkumar",
      twitter: "https://x.com/_1nt3rc3pt0r_",
      linkedin: "https://in.linkedin.com/in/sayooj-b-kumar-96a914195"
    },
    // Add more team members as needed
  ];

  return (
    <div className="container mx-auto px-4 py-8 max-w-7xl">
      <div className="bg-white rounded-lg shadow-md p-6">
        {/* <h1 className="text-2xl font-bold text-gray-800 mb-6">About ThreatShield</h1> */}
        
        <div className="space-y-8">
          {/* About ThreatShield Section */}
          <div>
            <h2 className="text-xl font-semibold text-gray-700 mb-4">What is ThreatShield?</h2>
            <div className="bg-gray-50 p-6 rounded-md border border-gray-200">
              <p className="text-gray-600 leading-relaxed">
                ThreatShield is a comprehensive threat modeling and security assessment platform designed to help organizations identify, analyze, and mitigate potential security risks in their systems. Our platform combines multiple security assessment methodologies including DREAD analysis, attack trees, and automated threat modeling to provide a holistic view of your system's security posture.
              </p>
              <div className="mt-4 space-y-2">
                <h3 className="font-medium text-gray-700">Key Features:</h3>
                <ul className="list-disc pl-5 text-gray-600 space-y-2">
                  <li>Automated Threat Modeling with AI assistance</li>
                  <li>DREAD Risk Assessment Framework</li>
                  <li>Interactive Attack Trees</li>
                  <li>Comprehensive Mitigation Strategies</li>
                  <li>Detailed Security Reports</li>
                  <li>Analytics and Insights Dashboard</li>
                </ul>
              </div>
              <div className="mt-6 flex justify-center">
                <img src="/image-20250327-090347.png" alt="ThreatShield Dashboard" className="rounded-lg shadow-md max-w-full" />
              </div>
            </div>
          </div>

          {/* License Section */}
          <div className="bg-gray-50 p-6 rounded-md border border-gray-200">
            <div className="flex items-center space-x-4 mb-4">
              <a href="https://opensource.org/licenses/MIT" target="_blank" rel="noopener noreferrer" className="inline-flex items-center px-4 py-2 bg-yellow-100 text-yellow-800 rounded-md hover:bg-yellow-200 transition-colors">
                <span className="text-sm font-medium">MIT License</span>
              </a>
              <a href="https://github.com/threatshield/threatshield" target="_blank" rel="noopener noreferrer" className="inline-flex items-center px-4 py-2 bg-blue-100 text-blue-800 rounded-md hover:bg-blue-200 transition-colors">
                <span className="text-sm font-medium">Version 2.0</span>
              </a>
            </div>
            <p className="text-gray-600">
              ThreatShield is open source software licensed under the MIT License. We welcome contributions from the community! Feel free to submit pull requests or open issues on our GitHub repository.
            </p>
          </div>

          {/* Team Section */}
          <div>
            <h2 className="text-xl font-semibold text-gray-700 mb-4">Meet the Team</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {teamMembers.map((member, index) => (
                <div key={index} className="bg-gray-50 p-6 rounded-md border border-gray-200">
                  <h3 className="font-semibold text-gray-800 mb-1">{member.name}</h3>
                  <p className="text-gray-600 mb-4">{member.role}</p>
                  <div className="flex space-x-4">
                    <a 
                      href={member.github}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-gray-600 hover:text-gray-900"
                    >
                      <svg className="h-5 w-5" fill="currentColor" viewBox="0 0 24 24">
                        <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/>
                      </svg>
                    </a>
                    <a 
                      href={member.twitter}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-gray-600 hover:text-gray-900"
                    >
                      <svg className="h-5 w-5" fill="currentColor" viewBox="0 0 24 24">
                        <path d="M23.953 4.57a10 10 0 01-2.825.775 4.958 4.958 0 002.163-2.723c-.951.555-2.005.959-3.127 1.184a4.92 4.92 0 00-8.384 4.482C7.69 8.095 4.067 6.13 1.64 3.162a4.822 4.822 0 00-.666 2.475c0 1.71.87 3.213 2.188 4.096a4.904 4.904 0 01-2.228-.616v.06a4.923 4.923 0 003.946 4.827 4.996 4.996 0 01-2.212.085 4.936 4.936 0 004.604 3.417 9.867 9.867 0 01-6.102 2.105c-.39 0-.779-.023-1.17-.067a13.995 13.995 0 007.557 2.209c9.053 0 13.998-7.496 13.998-13.985 0-.21 0-.42-.015-.63A9.935 9.935 0 0024 4.59z"/>
                      </svg>
                    </a>
                    <a 
                      href={member.linkedin}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-gray-600 hover:text-gray-900"
                    >
                      <svg className="h-5 w-5" fill="currentColor" viewBox="0 0 24 24">
                        <path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433c-1.144 0-2.063-.926-2.063-2.065 0-1.138.92-2.063 2.063-2.063 1.14 0 2.064.925 2.064 2.063 0 1.139-.925 2.065-2.064 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/>
                      </svg>
                    </a>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default About;
