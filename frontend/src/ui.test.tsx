import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import React from 'react';
import { Icon, Pill, RiskMeter } from './components';
import { SettingsView } from './view-settings';

// Mock context and global data
vi.mock('./api', () => ({
  MIRAGE_API: {
    get: vi.fn(() => Promise.resolve({ attacks: [] })),
  }
}));

describe('UI Smoke Tests', () => {
  it('Icon component renders without crashing', () => {
    const { container } = render(<Icon name="shield" />);
    expect(container.querySelector('svg')).toBeInTheDocument();
  });

  it('Pill component displays children', () => {
    render(<Pill kind="threat">Critical</Pill>);
    expect(screen.getByText('Critical')).toBeInTheDocument();
  });

  it('RiskMeter displays correct percentage', () => {
    render(<RiskMeter score={75} />);
    expect(screen.getByText('75')).toBeInTheDocument();
  });

  it('SettingsView renders correctly', () => {
    render(<SettingsView />);
    expect(screen.getByText(/Configuration/i)).toBeInTheDocument();
    expect(screen.getByText(/Configuration & Integrations/i)).toBeInTheDocument();
  });
});
