/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_REPO_OWNER?: string;
  readonly VITE_REPO_NAME?: string;
  readonly VITE_REPO_BRANCH?: string;
  readonly VITE_MAPPINGS_URL?: string;
  readonly VITE_OAUTH_WORKER_URL?: string;
  readonly VITE_GITHUB_CLIENT_ID?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
