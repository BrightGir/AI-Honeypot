import { describe, it, expect } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import { useTweaks } from './tweaks-panel';

describe('useTweaks', () => {
  it('should initialize with default values', () => {
    const defaults = { view: 'theater', speed: 1.5 };
    const { result } = renderHook(() => useTweaks(defaults));
    
    expect(result.current[0]).toEqual(defaults);
  });

  it('should update values', () => {
    const defaults = { view: 'theater' };
    const { result } = renderHook(() => useTweaks(defaults));
    
    act(() => {
      result.current[1]('view', 'wire');
    });
    
    expect(result.current[0].view).toBe('wire');
  });
});
