import { MirageAPIClient } from './api';

declare global {
  interface Window {
    MIRAGE_CONFIG?: any;
    MIRAGE_DATA?: any;
    MIRAGE_API?: MirageAPIClient;
  }
}
