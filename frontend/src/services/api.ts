import type { AnalysisResult, DetectionRule, ScanHistoryItem, Statistics } from '../types';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

export async function analyzeUrl(url: string): Promise<AnalysisResult> {
  const response = await fetch(`${API_BASE_URL}/api/analyze`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ url }),
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ detail: 'Failed to analyze URL' }));
    throw new Error(errorData.detail || 'An error occurred during analysis');
  }

  return response.json();
}

export async function getHistory(
  search?: string,
  classification?: string,
  limit: number = 50,
  offset: number = 0
): Promise<{ items: ScanHistoryItem[]; total: number; limit: number; offset: number }> {
  const params = new URLSearchParams();
  if (search) params.append('search', search);
  if (classification && classification !== 'ALL') params.append('classification', classification);
  params.append('limit', limit.toString());
  params.append('offset', offset.toString());

  const response = await fetch(`${API_BASE_URL}/api/history?${params.toString()}`);
  if (!response.ok) {
    throw new Error('Failed to fetch scan history');
  }
  return response.json();
}

export async function getScanById(id: number): Promise<AnalysisResult> {
  const response = await fetch(`${API_BASE_URL}/api/history/${id}`);
  if (!response.ok) {
    throw new Error(`Failed to fetch scan record #${id}`);
  }
  return response.json();
}

export async function deleteScan(id: number): Promise<void> {
  const response = await fetch(`${API_BASE_URL}/api/history/${id}`, {
    method: 'DELETE',
  });
  if (!response.ok) {
    throw new Error(`Failed to delete scan record #${id}`);
  }
}

export async function clearAllScans(): Promise<void> {
  const response = await fetch(`${API_BASE_URL}/api/history`, {
    method: 'DELETE',
  });
  if (!response.ok) {
    throw new Error('Failed to clear scan history');
  }
}

export async function getStatistics(): Promise<Statistics> {
  const response = await fetch(`${API_BASE_URL}/api/statistics`);
  if (!response.ok) {
    throw new Error('Failed to fetch platform statistics');
  }
  return response.json();
}

export async function getRules(): Promise<DetectionRule[]> {
  const response = await fetch(`${API_BASE_URL}/api/rules`);
  if (!response.ok) {
    throw new Error('Failed to fetch detection rules');
  }
  return response.json();
}

export async function getHealth(): Promise<{ status: string; ml_model_loaded: boolean }> {
  const response = await fetch(`${API_BASE_URL}/api/health`);
  if (!response.ok) {
    throw new Error('Backend health check failed');
  }
  return response.json();
}
