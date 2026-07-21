import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { API_BASE_URL } from '../services/api';

interface FeedbackEntry {
  uuid: string;
  assessment_id: string;
  assessment_name: string;
  created_for: string;
  created_at: string;
  submitted: boolean;
  submitted_at: string | null;
  answers: Record<string, unknown>;
}

interface Answers {
  threat_coverage: number;
  threat_accuracy: number;
  false_positive_count: number;
  missing_threats_count: number;
  dread_accuracy: number;
  mitigation_quality: number;
  test_case_relevance: number;
  overall_usefulness: number;
  would_recommend: number; // 1 = Yes, 0 = No
  improvement_suggestions: string;
}

const SCALE_QUESTIONS: { key: keyof Answers; label: string; description: string }[] = [
  {
    key: 'threat_coverage',
    label: 'Threat Coverage',
    description: 'How comprehensive was the threat model? Did it cover the relevant attack surfaces for your service?',
  },
  {
    key: 'threat_accuracy',
    label: 'Threat Accuracy',
    description: 'How accurate were the identified threats? Were they realistic and applicable to your service?',
  },
  {
    key: 'dread_accuracy',
    label: 'DREAD Score Accuracy',
    description: 'How accurate was the DREAD severity scoring for each threat?',
  },
  {
    key: 'mitigation_quality',
    label: 'Mitigation Quality',
    description: 'How actionable and practical were the suggested mitigations?',
  },
  {
    key: 'test_case_relevance',
    label: 'Test Case Relevance',
    description: 'How relevant were the generated security test cases to your service?',
  },
  {
    key: 'overall_usefulness',
    label: 'Overall Usefulness',
    description: 'Overall, how useful was this threat model for your security planning?',
  },
];

const COUNT_QUESTIONS: { key: keyof Answers; label: string; description: string }[] = [
  {
    key: 'false_positive_count',
    label: 'False Positives',
    description: 'How many of the identified threats were NOT applicable to your service?',
  },
  {
    key: 'missing_threats_count',
    label: 'Missing Threats',
    description: 'Approximately how many significant threats do you believe were missed?',
  },
];

const SCALE_LABELS = ['', 'Poor', 'Below Average', 'Average', 'Good', 'Excellent'];
const SCALE_COLORS = ['', 'bg-red-500', 'bg-orange-400', 'bg-yellow-400', 'bg-blue-400', 'bg-emerald-500'];

const defaultAnswers: Answers = {
  threat_coverage: 0,
  threat_accuracy: 0,
  false_positive_count: 0,
  missing_threats_count: 0,
  dread_accuracy: 0,
  mitigation_quality: 0,
  test_case_relevance: 0,
  overall_usefulness: 0,
  would_recommend: -1,
  improvement_suggestions: '',
};

const FeedbackPage: React.FC = () => {
  const { uuid } = useParams<{ uuid: string }>();
  const [feedback, setFeedback] = useState<FeedbackEntry | null>(null);
  const [answers, setAnswers] = useState<Answers>(defaultAnswers);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const load = async () => {
      try {
        const res = await fetch(`${API_BASE_URL}/feedback/${uuid}`);
        if (!res.ok) {
          setError('Feedback link not found or has expired.');
          return;
        }
        const data = await res.json();
        setFeedback(data.feedback);
        if (data.feedback.submitted) {
          setSubmitted(true);
        }
      } catch {
        setError('Unable to load the feedback form. Please try again later.');
      } finally {
        setLoading(false);
      }
    };
    if (uuid) load();
  }, [uuid]);

  const setScale = (key: keyof Answers, value: number) => {
    setAnswers(prev => ({ ...prev, [key]: value }));
  };

  const allRequiredAnswered = (): boolean => {
    return (
      SCALE_QUESTIONS.every(q => (answers[q.key] as number) > 0) &&
      answers.would_recommend !== -1
    );
  };

  const handleSubmit = async () => {
    if (!allRequiredAnswered()) return;
    setSubmitting(true);
    try {
      const res = await fetch(`${API_BASE_URL}/feedback/${uuid}/submit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ answers }),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        setError(data.error || 'Submission failed. Please try again.');
        return;
      }
      setSubmitted(true);
    } catch {
      setError('Network error. Please check your connection and try again.');
    } finally {
      setSubmitting(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-[#0a1628] flex items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <div className="relative w-12 h-12">
            <div className="absolute inset-0 rounded-full border-2 border-gray-700" />
            <div className="absolute inset-0 rounded-full border-2 border-t-[#0052cc] animate-spin" />
          </div>
          <p className="text-sm text-slate-400">Loading feedback form…</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-[#0a1628] flex items-center justify-center px-4">
        <div className="max-w-md w-full text-center">
          <div className="w-14 h-14 rounded-full bg-red-900/30 border border-red-800/40 flex items-center justify-center mx-auto mb-4">
            <svg className="w-7 h-7 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </div>
          <h1 className="text-lg font-semibold text-slate-100 mb-2">Something went wrong</h1>
          <p className="text-sm text-slate-400">{error}</p>
        </div>
      </div>
    );
  }

  if (submitted) {
    return (
      <div className="min-h-screen bg-[#0a1628] flex items-center justify-center px-4">
        <div className="max-w-lg w-full text-center">
          <div className="w-16 h-16 rounded-full bg-emerald-900/30 border border-emerald-800/40 flex items-center justify-center mx-auto mb-5">
            <svg className="w-8 h-8 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </div>
          <h1 className="text-2xl font-bold text-slate-100 mb-2">Thank you!</h1>
          <p className="text-slate-400 mb-3">
            Your feedback on <span className="text-white font-medium">{feedback?.assessment_name}</span> has been recorded.
          </p>
          <p className="text-xs text-slate-500">This form cannot be edited after submission.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#0a1628]" style={{ backgroundImage: 'radial-gradient(ellipse at 50% 0%, rgba(0,82,204,0.08) 0%, transparent 60%)' }}>
      <div className="max-w-2xl mx-auto px-4 py-12">

        {/* Header */}
        <div className="mb-8 text-center">
          <div className="inline-flex items-center gap-2 mb-4">
            <div className="w-8 h-8 rounded-lg bg-[#0052cc] flex items-center justify-center shadow-lg shadow-blue-900/50">
              <svg style={{ width: 14, height: 14 }} fill="none" viewBox="0 0 24 24" stroke="white" strokeWidth={2.2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </div>
            <span className="text-lg font-bold text-white"><span className="text-blue-300">Threat</span>Shield</span>
          </div>
          <h1 className="text-2xl font-bold text-slate-100 mb-2">Threat Model Feedback</h1>
          <p className="text-slate-400 text-sm">
            Assessment: <span className="text-white font-medium">{feedback?.assessment_name}</span>
          </p>
          <p className="text-slate-500 text-xs mt-1">
            Your responses help improve the quality of future threat models.
          </p>
        </div>

        {error && (
          <div className="mb-6 px-4 py-3 rounded-lg bg-red-900/20 border border-red-800/40 text-red-400 text-sm">
            {error}
          </div>
        )}

        {/* Scale Questions */}
        <div className="space-y-5">
          <div className="bg-gray-900/60 rounded-xl border border-gray-700/40 overflow-hidden">
            <div className="px-5 py-3.5 border-b border-gray-800/60">
              <h2 className="text-xs font-semibold uppercase tracking-widest text-slate-400">Quality Ratings</h2>
              <p className="text-xs text-slate-500 mt-0.5">Rate each dimension from 1 (Poor) to 5 (Excellent)</p>
            </div>
            <div className="divide-y divide-gray-800/40">
              {SCALE_QUESTIONS.map((q, i) => {
                const val = answers[q.key] as number;
                return (
                  <div key={q.key} className="px-5 py-4">
                    <div className="flex items-start justify-between gap-4 mb-3">
                      <div>
                        <p className="text-sm font-medium text-slate-200">
                          <span className="text-slate-500 mr-1.5">{i + 1}.</span>{q.label}
                          <span className="text-red-400 ml-0.5">*</span>
                        </p>
                        <p className="text-xs text-slate-500 mt-0.5">{q.description}</p>
                      </div>
                      {val > 0 && (
                        <span className={`flex-shrink-0 text-xs font-semibold px-2 py-0.5 rounded-full text-white ${SCALE_COLORS[val]}`}>
                          {SCALE_LABELS[val]}
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-2">
                      {[1, 2, 3, 4, 5].map(n => (
                        <button
                          key={n}
                          onClick={() => setScale(q.key, n)}
                          className={`flex-1 py-2 rounded-lg text-sm font-semibold transition-all border ${
                            val === n
                              ? `${SCALE_COLORS[n]} text-white border-transparent shadow-sm`
                              : 'bg-gray-800/60 text-slate-400 border-gray-700/40 hover:bg-gray-700/60 hover:text-slate-200'
                          }`}
                        >
                          {n}
                        </button>
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Count Questions */}
          <div className="bg-gray-900/60 rounded-xl border border-gray-700/40 overflow-hidden">
            <div className="px-5 py-3.5 border-b border-gray-800/60">
              <h2 className="text-xs font-semibold uppercase tracking-widest text-slate-400">Gap Analysis</h2>
              <p className="text-xs text-slate-500 mt-0.5">Enter a numeric count (0 if none)</p>
            </div>
            <div className="divide-y divide-gray-800/40">
              {COUNT_QUESTIONS.map((q, i) => {
                const val = answers[q.key] as number;
                return (
                  <div key={q.key} className="px-5 py-4">
                    <p className="text-sm font-medium text-slate-200 mb-0.5">
                      <span className="text-slate-500 mr-1.5">{SCALE_QUESTIONS.length + i + 1}.</span>{q.label}
                    </p>
                    <p className="text-xs text-slate-500 mb-3">{q.description}</p>
                    <div className="flex items-center gap-3">
                      <button
                        onClick={() => setScale(q.key, Math.max(0, val - 1))}
                        className="w-8 h-8 rounded-lg bg-gray-800/60 border border-gray-700/40 text-slate-300 hover:bg-gray-700/60 flex items-center justify-center text-lg font-semibold transition-all"
                        aria-label="Decrease"
                      >
                        −
                      </button>
                      <input
                        type="number"
                        min={0}
                        max={20}
                        value={val}
                        onChange={e => setScale(q.key, Math.max(0, Math.min(20, parseInt(e.target.value) || 0)))}
                        className="w-16 text-center py-1.5 rounded-lg bg-gray-800/60 border border-gray-700/40 text-slate-100 text-sm font-semibold focus:outline-none focus:ring-2 focus:ring-[#0052cc]/40"
                      />
                      <button
                        onClick={() => setScale(q.key, Math.min(20, val + 1))}
                        className="w-8 h-8 rounded-lg bg-gray-800/60 border border-gray-700/40 text-slate-300 hover:bg-gray-700/60 flex items-center justify-center text-lg font-semibold transition-all"
                        aria-label="Increase"
                      >
                        +
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Would Recommend */}
          <div className="bg-gray-900/60 rounded-xl border border-gray-700/40 px-5 py-4">
            <p className="text-sm font-medium text-slate-200 mb-0.5">
              <span className="text-slate-500 mr-1.5">{SCALE_QUESTIONS.length + COUNT_QUESTIONS.length + 1}.</span>
              Would you recommend ThreatShield to other teams?
              <span className="text-red-400 ml-0.5">*</span>
            </p>
            <p className="text-xs text-slate-500 mb-3">Based on the quality of this threat model assessment.</p>
            <div className="flex gap-3">
              {[{ label: 'Yes', value: 1 }, { label: 'No', value: 0 }].map(opt => (
                <button
                  key={opt.label}
                  onClick={() => setAnswers(prev => ({ ...prev, would_recommend: opt.value }))}
                  className={`flex-1 py-2.5 rounded-lg text-sm font-semibold transition-all border ${
                    answers.would_recommend === opt.value
                      ? opt.value === 1
                        ? 'bg-emerald-500 text-white border-transparent shadow-sm'
                        : 'bg-red-500 text-white border-transparent shadow-sm'
                      : 'bg-gray-800/60 text-slate-400 border-gray-700/40 hover:bg-gray-700/60 hover:text-slate-200'
                  }`}
                >
                  {opt.label}
                </button>
              ))}
            </div>
          </div>

          {/* Improvement Suggestions */}
          <div className="bg-gray-900/60 rounded-xl border border-gray-700/40 px-5 py-4">
            <p className="text-sm font-medium text-slate-200 mb-0.5">
              <span className="text-slate-500 mr-1.5">{SCALE_QUESTIONS.length + COUNT_QUESTIONS.length + 2}.</span>
              Improvement Suggestions
              <span className="text-slate-500 ml-1.5 text-xs font-normal">(optional)</span>
            </p>
            <p className="text-xs text-slate-500 mb-3">
              What specific threats, mitigations, or improvements were missing? Your input directly shapes future model quality.
            </p>
            <textarea
              rows={4}
              value={answers.improvement_suggestions}
              onChange={e => setAnswers(prev => ({ ...prev, improvement_suggestions: e.target.value }))}
              placeholder="e.g. The model missed rate limiting threats on the payment API. The DREAD scores for injection attacks seemed low…"
              className="w-full px-3 py-2.5 text-sm bg-gray-800/60 border border-gray-700/40 rounded-lg text-slate-200 placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-[#0052cc]/40 resize-none"
            />
          </div>
        </div>

        {/* Submit */}
        <div className="mt-7 flex flex-col items-center gap-3">
          {!allRequiredAnswered() && (
            <p className="text-xs text-slate-500">Please answer all required questions (<span className="text-red-400">*</span>) before submitting.</p>
          )}
          <button
            onClick={handleSubmit}
            disabled={submitting || !allRequiredAnswered()}
            className="w-full max-w-xs py-3 rounded-xl bg-[#0052cc] text-white text-sm font-semibold hover:bg-[#0047b3] transition-all focus:outline-none focus:ring-2 focus:ring-[#0052cc] focus:ring-offset-2 focus:ring-offset-[#0a1628] disabled:opacity-50 disabled:cursor-not-allowed shadow-lg shadow-blue-900/40"
          >
            {submitting ? (
              <span className="flex items-center justify-center gap-2">
                <svg className="animate-spin h-4 w-4" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                Submitting…
              </span>
            ) : 'Submit Feedback'}
          </button>
          <p className="text-xs text-slate-600">Submissions are final and cannot be edited.</p>
        </div>

      </div>
    </div>
  );
};

export default FeedbackPage;
