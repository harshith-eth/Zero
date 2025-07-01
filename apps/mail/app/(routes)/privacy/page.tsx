'use client';

import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { Progress } from '@/components/ui/progress';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { 
  Shield, 
  Lock, 
  Key, 
  Download, 
  Trash2, 
  AlertCircle,
  CheckCircle,
  RefreshCw,
  Eye,
  EyeOff,
  FileKey,
  UserX
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

interface PrivacySettings {
  e2eEnabled: boolean;
  anonymousAnalytics: boolean;
  metadataCollection: 'none' | 'minimal' | 'full';
  dataRetentionDays: number;
  autoDeleteEnabled: boolean;
}

interface EncryptionStats {
  totalEmails: number;
  encryptedEmails: number;
  pgpKeysGenerated: boolean;
  lastKeyRotation?: Date;
}

export default function PrivacyDashboard() {
  const [settings, setSettings] = useState<PrivacySettings>({
    e2eEnabled: false,
    anonymousAnalytics: false,
    metadataCollection: 'minimal',
    dataRetentionDays: 365,
    autoDeleteEnabled: false,
  });

  const [stats, setStats] = useState<EncryptionStats>({
    totalEmails: 0,
    encryptedEmails: 0,
    pgpKeysGenerated: false,
  });

  const [loading, setLoading] = useState(false);
  const { toast } = useToast();

  useEffect(() => {
    loadPrivacySettings();
    loadEncryptionStats();
  }, []);

  const loadPrivacySettings = async () => {
    try {
      const response = await fetch('/api/privacy/settings');
      const data = await response.json();
      setSettings(data);
    } catch (error) {
      console.error('Failed to load privacy settings:', error);
    }
  };

  const loadEncryptionStats = async () => {
    try {
      const response = await fetch('/api/privacy/stats');
      const data = await response.json();
      setStats(data);
    } catch (error) {
      console.error('Failed to load encryption stats:', error);
    }
  };

  const updateSetting = async (key: keyof PrivacySettings, value: any) => {
    try {
      setLoading(true);
      const response = await fetch('/api/privacy/settings', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ [key]: value }),
      });

      if (response.ok) {
        setSettings(prev => ({ ...prev, [key]: value }));
        toast({
          title: 'Settings updated',
          description: 'Your privacy settings have been updated successfully.',
        });
      }
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to update settings. Please try again.',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  const generatePGPKeys = async () => {
    try {
      setLoading(true);
      const response = await fetch('/api/encryption/generate-keys', {
        method: 'POST',
      });

      if (response.ok) {
        toast({
          title: 'Keys generated',
          description: 'Your PGP encryption keys have been generated successfully.',
        });
        loadEncryptionStats();
      }
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to generate keys. Please try again.',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  const rotateKeys = async () => {
    try {
      setLoading(true);
      const response = await fetch('/api/encryption/rotate-keys', {
        method: 'POST',
      });

      if (response.ok) {
        toast({
          title: 'Keys rotated',
          description: 'Your encryption keys have been rotated successfully.',
        });
        loadEncryptionStats();
      }
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to rotate keys. Please try again.',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  const exportData = async () => {
    try {
      setLoading(true);
      const response = await fetch('/api/privacy/export-data');
      const blob = await response.blob();
      
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `zero-data-export-${new Date().toISOString()}.zip`;
      a.click();
      
      toast({
        title: 'Data exported',
        description: 'Your data has been exported successfully.',
      });
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to export data. Please try again.',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  const deleteAllData = async () => {
    if (!confirm('Are you sure you want to delete all your data? This action cannot be undone.')) {
      return;
    }

    try {
      setLoading(true);
      const response = await fetch('/api/privacy/delete-all', {
        method: 'DELETE',
      });

      if (response.ok) {
        toast({
          title: 'Data deleted',
          description: 'All your data has been permanently deleted.',
        });
        // Redirect to login or home
        window.location.href = '/';
      }
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to delete data. Please try again.',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  const encryptionPercentage = stats.totalEmails > 0 
    ? (stats.encryptedEmails / stats.totalEmails) * 100 
    : 0;

  return (
    <div className="container mx-auto p-6 max-w-4xl">
      <div className="mb-8">
        <h1 className="text-3xl font-bold mb-2">Privacy & Security</h1>
        <p className="text-muted-foreground">
          Manage your privacy settings and encryption preferences
        </p>
      </div>

      <Tabs defaultValue="overview" className="space-y-6">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="encryption">Encryption</TabsTrigger>
          <TabsTrigger value="privacy">Privacy</TabsTrigger>
          <TabsTrigger value="data">Data Management</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-6">
          <div className="grid gap-6 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Shield className="h-5 w-5" />
                  Security Status
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center justify-between">
                  <span>End-to-End Encryption</span>
                  {settings.e2eEnabled ? (
                    <CheckCircle className="h-5 w-5 text-green-500" />
                  ) : (
                    <AlertCircle className="h-5 w-5 text-yellow-500" />
                  )}
                </div>
                <div className="flex items-center justify-between">
                  <span>PGP Keys Generated</span>
                  {stats.pgpKeysGenerated ? (
                    <CheckCircle className="h-5 w-5 text-green-500" />
                  ) : (
                    <AlertCircle className="h-5 w-5 text-yellow-500" />
                  )}
                </div>
                <div className="flex items-center justify-between">
                  <span>Auto-Delete Enabled</span>
                  {settings.autoDeleteEnabled ? (
                    <CheckCircle className="h-5 w-5 text-green-500" />
                  ) : (
                    <AlertCircle className="h-5 w-5 text-yellow-500" />
                  )}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Lock className="h-5 w-5" />
                  Encryption Statistics
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <div className="flex justify-between mb-2">
                    <span className="text-sm">Encrypted Emails</span>
                    <span className="text-sm font-medium">
                      {stats.encryptedEmails} / {stats.totalEmails}
                    </span>
                  </div>
                  <Progress value={encryptionPercentage} />
                </div>
                {stats.lastKeyRotation && (
                  <div className="text-sm text-muted-foreground">
                    Last key rotation: {new Date(stats.lastKeyRotation).toLocaleDateString()}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {!stats.pgpKeysGenerated && (
            <Alert>
              <AlertCircle className="h-4 w-4" />
              <AlertTitle>Setup Required</AlertTitle>
              <AlertDescription>
                Generate your PGP keys to enable end-to-end encryption for your emails.
                <Button 
                  size="sm" 
                  className="mt-2"
                  onClick={generatePGPKeys}
                  disabled={loading}
                >
                  Generate Keys
                </Button>
              </AlertDescription>
            </Alert>
          )}
        </TabsContent>

        <TabsContent value="encryption" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Encryption Settings</CardTitle>
              <CardDescription>
                Configure how your emails and data are encrypted
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <Label htmlFor="e2e">End-to-End Encryption</Label>
                  <p className="text-sm text-muted-foreground">
                    Encrypt emails so only recipients can read them
                  </p>
                </div>
                <Switch
                  id="e2e"
                  checked={settings.e2eEnabled}
                  onCheckedChange={(checked) => updateSetting('e2eEnabled', checked)}
                  disabled={loading || !stats.pgpKeysGenerated}
                />
              </div>

              <div className="pt-4 space-y-4">
                <Button
                  variant="outline"
                  className="w-full"
                  onClick={rotateKeys}
                  disabled={loading || !stats.pgpKeysGenerated}
                >
                  <RefreshCw className="mr-2 h-4 w-4" />
                  Rotate Encryption Keys
                </Button>

                <Button
                  variant="outline"
                  className="w-full"
                  onClick={() => {/* TODO: Implement key export */}}
                  disabled={loading || !stats.pgpKeysGenerated}
                >
                  <FileKey className="mr-2 h-4 w-4" />
                  Export Encryption Keys
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="privacy" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Privacy Settings</CardTitle>
              <CardDescription>
                Control how your data is collected and used
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <Label htmlFor="analytics">Anonymous Analytics</Label>
                  <p className="text-sm text-muted-foreground">
                    Help improve Zero with anonymous usage data
                  </p>
                </div>
                <Switch
                  id="analytics"
                  checked={settings.anonymousAnalytics}
                  onCheckedChange={(checked) => updateSetting('anonymousAnalytics', checked)}
                  disabled={loading}
                />
              </div>

              <div className="space-y-2">
                <Label>Metadata Collection</Label>
                <select
                  className="w-full p-2 border rounded"
                  value={settings.metadataCollection}
                  onChange={(e) => updateSetting('metadataCollection', e.target.value)}
                  disabled={loading}
                >
                  <option value="none">None - Maximum privacy</option>
                  <option value="minimal">Minimal - Basic functionality only</option>
                  <option value="full">Full - All features enabled</option>
                </select>
                <p className="text-sm text-muted-foreground">
                  Controls what metadata is stored with your emails
                </p>
              </div>

              <div className="space-y-2">
                <Label>Data Retention</Label>
                <select
                  className="w-full p-2 border rounded"
                  value={settings.dataRetentionDays}
                  onChange={(e) => updateSetting('dataRetentionDays', parseInt(e.target.value))}
                  disabled={loading}
                >
                  <option value={30}>30 days</option>
                  <option value={90}>90 days</option>
                  <option value={180}>180 days</option>
                  <option value={365}>1 year</option>
                  <option value={-1}>Forever</option>
                </select>
                <p className="text-sm text-muted-foreground">
                  How long to keep deleted emails and data
                </p>
              </div>

              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <Label htmlFor="auto-delete">Auto-Delete Old Data</Label>
                  <p className="text-sm text-muted-foreground">
                    Automatically delete data older than retention period
                  </p>
                </div>
                <Switch
                  id="auto-delete"
                  checked={settings.autoDeleteEnabled}
                  onCheckedChange={(checked) => updateSetting('autoDeleteEnabled', checked)}
                  disabled={loading}
                />
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="data" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Data Management</CardTitle>
              <CardDescription>
                Export or delete your personal data
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <Button
                variant="outline"
                className="w-full"
                onClick={exportData}
                disabled={loading}
              >
                <Download className="mr-2 h-4 w-4" />
                Export All Data
              </Button>

              <Alert>
                <AlertCircle className="h-4 w-4" />
                <AlertTitle>Data Export</AlertTitle>
                <AlertDescription>
                  Download all your emails, settings, and encryption keys in a portable format.
                  The export will be encrypted with your account password.
                </AlertDescription>
              </Alert>

              <div className="pt-6 border-t">
                <h3 className="text-lg font-semibold mb-4 text-destructive">Danger Zone</h3>
                <Button
                  variant="destructive"
                  className="w-full"
                  onClick={deleteAllData}
                  disabled={loading}
                >
                  <Trash2 className="mr-2 h-4 w-4" />
                  Delete All Data
                </Button>
                <p className="text-sm text-muted-foreground mt-2">
                  Permanently delete your account and all associated data. This action cannot be undone.
                </p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}