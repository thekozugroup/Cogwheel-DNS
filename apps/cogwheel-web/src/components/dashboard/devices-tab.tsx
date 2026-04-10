import { useMemo, useState } from "react";
import { useCogwheel } from "@/contexts/cogwheel-context";
import { api, type DeviceServiceOverride, type SettingsSummary } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

export function DevicesTab() {
  const { settings, busyAction, setBusyAction, pushToast, load } =
    useCogwheel();

  const [deviceId, setDeviceId] = useState<string | null>(null);
  const [deviceName, setDeviceName] = useState("");
  const [deviceIpAddress, setDeviceIpAddress] = useState("");
  const [devicePolicyMode, setDevicePolicyMode] = useState<
    "global" | "custom"
  >("global");
  const [deviceProfileOverride, setDeviceProfileOverride] = useState("");
  const [deviceProtectionOverride, setDeviceProtectionOverride] = useState<
    "inherit" | "bypass"
  >("inherit");
  const [deviceAllowedDomains, setDeviceAllowedDomains] = useState("");
  const [deviceServiceOverrides, setDeviceServiceOverrides] = useState<
    DeviceServiceOverride[]
  >([]);
  const [deviceServiceOverrideId, setDeviceServiceOverrideId] = useState("");
  const [deviceServiceOverrideMode, setDeviceServiceOverrideMode] = useState<
    "allow" | "block"
  >("allow");

  const serviceLabelMap = useMemo(
    () =>
      new Map(
        settings.services.map((service) => [
          service.manifest.service_id,
          service.manifest.display_name,
        ]),
      ),
    [settings.services],
  );

  const serviceInfoMap = useMemo(
    () =>
      new Map(
        settings.services.map((service) => [
          service.manifest.service_id,
          service.manifest,
        ]),
      ),
    [settings.services],
  );

  const selectedDeviceServiceManifest = useMemo(
    () =>
      deviceServiceOverrideId
        ? serviceInfoMap.get(deviceServiceOverrideId) ?? null
        : null,
    [deviceServiceOverrideId, serviceInfoMap],
  );

  const pendingDeviceServiceOverride = useMemo(
    () =>
      deviceServiceOverrides.find(
        (item) => item.service_id === deviceServiceOverrideId,
      ) ?? null,
    [deviceServiceOverrideId, deviceServiceOverrides],
  );

  const deviceServiceOverrideIsNoop =
    pendingDeviceServiceOverride?.mode === deviceServiceOverrideMode;

  const deviceServiceOverridePreview = useMemo(() => {
    if (!selectedDeviceServiceManifest) return null;

    const domains =
      deviceServiceOverrideMode === "allow"
        ? Array.from(
            new Set([
              ...selectedDeviceServiceManifest.allow_domains,
              ...selectedDeviceServiceManifest.block_domains,
              ...selectedDeviceServiceManifest.exceptions,
            ]),
          )
        : selectedDeviceServiceManifest.block_domains;

    return {
      serviceId: selectedDeviceServiceManifest.service_id,
      displayName: selectedDeviceServiceManifest.display_name,
      category: selectedDeviceServiceManifest.category,
      riskNotes: selectedDeviceServiceManifest.risk_notes,
      domains,
      exceptions: selectedDeviceServiceManifest.exceptions,
      sampleDomains: domains.slice(0, 4),
    };
  }, [deviceServiceOverrideMode, selectedDeviceServiceManifest]);

  function resetDeviceForm() {
    setDeviceId(null);
    setDeviceName("");
    setDeviceIpAddress("");
    setDevicePolicyMode("global");
    setDeviceProfileOverride("");
    setDeviceProtectionOverride("inherit");
    setDeviceAllowedDomains("");
    setDeviceServiceOverrides([]);
    setDeviceServiceOverrideId("");
    setDeviceServiceOverrideMode("allow");
  }

  async function handleDeviceSubmit() {
    setBusyAction("device-submit");
    try {
      await api.upsertDevice({
        id: deviceId ?? undefined,
        name: deviceName,
        ip_address: deviceIpAddress,
        policy_mode: devicePolicyMode,
        blocklist_profile_override:
          devicePolicyMode === "custom"
            ? deviceProfileOverride || null
            : null,
        protection_override:
          devicePolicyMode === "custom" ? deviceProtectionOverride : "inherit",
        allowed_domains:
          devicePolicyMode === "custom"
            ? deviceAllowedDomains
                .split(",")
                .map((domain) => domain.trim())
                .filter(Boolean)
            : [],
        service_overrides:
          devicePolicyMode === "custom" ? deviceServiceOverrides : [],
      });
      pushToast(
        deviceId ? "Device updated" : "Device added",
        `${deviceName} is now tracked in the control plane.`,
        "success",
      );
      resetDeviceForm();
      await load();
    } catch (mutationError) {
      pushToast(
        "Device save failed",
        mutationError instanceof Error
          ? mutationError.message
          : "Unknown error",
        "error",
      );
    } finally {
      setBusyAction(null);
    }
  }

  function startDeviceEdit(device: SettingsSummary["devices"][number]) {
    setDeviceId(device.id);
    setDeviceName(device.name);
    setDeviceIpAddress(device.ip_address);
    setDevicePolicyMode(device.policy_mode);
    setDeviceProfileOverride(device.blocklist_profile_override ?? "");
    setDeviceProtectionOverride(device.protection_override);
    setDeviceAllowedDomains(device.allowed_domains.join(", "));
    setDeviceServiceOverrides(device.service_overrides);
    setDeviceServiceOverrideId("");
    setDeviceServiceOverrideMode("allow");
  }

  function addDeviceServiceOverride() {
    if (devicePolicyMode !== "custom") {
      pushToast(
        "Custom mode required",
        "Switch the device to custom policy mode before adding service rules.",
        "error",
      );
      return;
    }
    if (!deviceServiceOverrideId) {
      pushToast(
        "Service required",
        "Choose a built-in service before adding a device rule.",
        "error",
      );
      return;
    }
    if (!selectedDeviceServiceManifest) {
      pushToast(
        "Unknown service",
        "Reload settings and pick the service again before saving the device rule.",
        "error",
      );
      return;
    }
    if (
      !deviceServiceOverridePreview ||
      deviceServiceOverridePreview.domains.length === 0
    ) {
      pushToast(
        "Service rule unavailable",
        "This service does not currently expand into any device-specific domains for the selected mode.",
        "error",
      );
      return;
    }
    if (deviceServiceOverrideIsNoop) {
      pushToast(
        "Service rule already queued",
        `${selectedDeviceServiceManifest.display_name} is already using ${deviceServiceOverrideMode} mode for this device.`,
        "error",
      );
      return;
    }

    setDeviceServiceOverrides((current) => {
      const next = current.filter(
        (item) => item.service_id !== deviceServiceOverrideId,
      );
      next.push({
        service_id: deviceServiceOverrideId,
        mode: deviceServiceOverrideMode,
      });
      next.sort((left, right) =>
        left.service_id.localeCompare(right.service_id),
      );
      return next;
    });
    pushToast(
      "Service rule added",
      pendingDeviceServiceOverride
        ? `${selectedDeviceServiceManifest.display_name} now uses ${deviceServiceOverrideMode} mode for this device.`
        : `${selectedDeviceServiceManifest.display_name} expands into ${deviceServiceOverridePreview.domains.length} device-specific domain rule${deviceServiceOverridePreview.domains.length === 1 ? "" : "s"}.`,
      "success",
    );
  }

  function removeDeviceServiceOverride(serviceId: string) {
    setDeviceServiceOverrides((current) =>
      current.filter((item) => item.service_id !== serviceId),
    );
  }

  function formatDeviceServiceOverride(
    serviceId: string,
    mode: "allow" | "block",
  ) {
    const label = serviceLabelMap.get(serviceId) ?? serviceId;
    return `${label} - ${mode}`;
  }

  function describeDeviceServiceOverride(serviceId: string) {
    const info = serviceInfoMap.get(serviceId);
    if (!info) return "Custom device service rule";
    return `${info.category} - ${info.risk_notes}`;
  }

  return (
    <div className="p-4 md:p-6 space-y-4">
      <div className="grid gap-6 xl:grid-cols-[1.05fr_0.95fr]">
        {/* Left: Device form card */}
        <Card>
          <CardHeader>
            <CardTitle>{deviceId ? "Edit Device" : "Add Device"}</CardTitle>
            <CardDescription>
              Register a device with a name and IP address
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="device-name">Device name</Label>
                <Input
                  id="device-name"
                  value={deviceName}
                  onChange={(event) => setDeviceName(event.target.value)}
                  placeholder="Kitchen iPad"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="device-ip">IP Address</Label>
                <Input
                  id="device-ip"
                  value={deviceIpAddress}
                  onChange={(event) => setDeviceIpAddress(event.target.value)}
                  placeholder="192.168.1.42"
                />
              </div>
            </div>

            <div className="grid gap-3 sm:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="device-policy">Policy mode</Label>
                <select
                  id="device-policy"
                  className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                  value={devicePolicyMode}
                  onChange={(event) =>
                    setDevicePolicyMode(
                      event.target.value as "global" | "custom",
                    )
                  }
                >
                  <option value="global">Household default</option>
                  <option value="custom">Custom assignment</option>
                </select>
              </div>
              <div className="space-y-2">
                <Label htmlFor="device-profile">Profile override</Label>
                <select
                  id="device-profile"
                  className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50"
                  value={deviceProfileOverride}
                  onChange={(event) =>
                    setDeviceProfileOverride(event.target.value)
                  }
                  disabled={devicePolicyMode !== "custom"}
                >
                  <option value="">Choose a saved profile</option>
                  {settings.block_profiles.map((profile) => (
                    <option key={profile.id} value={profile.name}>
                      {profile.emoji} {profile.name}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <div className="grid gap-3 sm:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="device-protection">Protection</Label>
                <select
                  id="device-protection"
                  className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50"
                  value={deviceProtectionOverride}
                  onChange={(event) =>
                    setDeviceProtectionOverride(
                      event.target.value as "inherit" | "bypass",
                    )
                  }
                  disabled={devicePolicyMode !== "custom"}
                >
                  <option value="inherit">Keep blocking on</option>
                  <option value="bypass">Bypass blocking</option>
                </select>
              </div>
              <div className="space-y-2">
                <Label htmlFor="device-allowed">Allowed domains</Label>
                <Input
                  id="device-allowed"
                  value={deviceAllowedDomains}
                  onChange={(event) =>
                    setDeviceAllowedDomains(event.target.value)
                  }
                  placeholder="school.site, printer.local"
                  disabled={devicePolicyMode !== "custom"}
                />
              </div>
            </div>

            {/* Service override section */}
            <div className="space-y-3 rounded-lg border border-border p-4">
              <div className="space-y-1">
                <div className="text-sm font-medium">Service override</div>
                <p className="text-sm text-muted-foreground">
                  Add a focused allow or block rule for a known service when this
                  device needs a small exception.
                </p>
              </div>
              <div className="grid gap-3 xl:grid-cols-[minmax(0,1fr)_180px_auto]">
                <select
                  className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50"
                  value={deviceServiceOverrideId}
                  onChange={(event) =>
                    setDeviceServiceOverrideId(event.target.value)
                  }
                  disabled={devicePolicyMode !== "custom"}
                >
                  <option value="">Select service override</option>
                  {settings.services.map((service) => (
                    <option
                      key={service.manifest.service_id}
                      value={service.manifest.service_id}
                    >
                      {service.manifest.display_name}
                    </option>
                  ))}
                </select>
                <select
                  className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50"
                  value={deviceServiceOverrideMode}
                  onChange={(event) =>
                    setDeviceServiceOverrideMode(
                      event.target.value as "allow" | "block",
                    )
                  }
                  disabled={devicePolicyMode !== "custom"}
                >
                  <option value="allow">Allow service</option>
                  <option value="block">Block service</option>
                </select>
                <Button
                  variant="outline"
                  onClick={addDeviceServiceOverride}
                  disabled={
                    devicePolicyMode !== "custom" ||
                    !deviceServiceOverrideId ||
                    deviceServiceOverrideIsNoop
                  }
                >
                  Add service rule
                </Button>
              </div>
            </div>

            {/* Service override preview */}
            {deviceServiceOverrideId && deviceServiceOverridePreview ? (
              <div className="rounded-lg border border-border p-4 text-sm">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <div className="font-medium">
                      {deviceServiceOverridePreview.displayName}
                    </div>
                    <div className="mt-1 text-muted-foreground">
                      {deviceServiceOverridePreview.riskNotes}
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <Badge>{deviceServiceOverrideMode}</Badge>
                    <Badge variant="secondary">
                      {deviceServiceOverridePreview.category}
                    </Badge>
                    <Badge variant="secondary">
                      {deviceServiceOverridePreview.domains.length} domains
                    </Badge>
                  </div>
                </div>
                <div className="mt-3 flex flex-wrap gap-2">
                  {deviceServiceOverridePreview.sampleDomains.map((domain) => (
                    <Badge key={domain} variant="outline">
                      {domain}
                    </Badge>
                  ))}
                </div>
              </div>
            ) : null}

            {/* Queued service overrides */}
            {deviceServiceOverrides.length > 0 ? (
              <div className="flex flex-wrap gap-2">
                {deviceServiceOverrides.map((override) => (
                  <button
                    key={`${override.service_id}-${override.mode}`}
                    type="button"
                    title={describeDeviceServiceOverride(override.service_id)}
                    className="rounded-full border border-border bg-background px-3 py-1 text-xs text-muted-foreground transition hover:bg-muted/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                    onClick={() =>
                      removeDeviceServiceOverride(override.service_id)
                    }
                  >
                    {formatDeviceServiceOverride(
                      override.service_id,
                      override.mode,
                    )}{" "}
                    x
                  </button>
                ))}
              </div>
            ) : null}

            {/* Household default notice */}
            {devicePolicyMode !== "custom" ? (
              <p className="rounded-lg border border-dashed border-border p-4 text-sm text-muted-foreground">
                This device will follow the household default until you switch it
                to a custom assignment.
              </p>
            ) : null}
          </CardContent>
          <CardFooter className="justify-end gap-2">
            {deviceId ? (
              <Button variant="ghost" onClick={resetDeviceForm}>
                Cancel
              </Button>
            ) : null}
            <Button
              onClick={() => void handleDeviceSubmit()}
              disabled={
                !deviceName ||
                !deviceIpAddress ||
                busyAction === "device-submit"
              }
            >
              {busyAction === "device-submit"
                ? "Saving..."
                : deviceId
                  ? "Save device"
                  : "Add device"}
            </Button>
          </CardFooter>
        </Card>

        {/* Right: Saved devices table */}
        <Card>
          <CardHeader>
            <CardTitle>Devices</CardTitle>
            <CardDescription>
              Named devices tracked by the control plane
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>IP Address</TableHead>
                  <TableHead>Policy</TableHead>
                  <TableHead>Profile</TableHead>
                  <TableHead>Protection</TableHead>
                  <TableHead></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {settings.devices.length === 0 ? (
                  <TableRow>
                    <TableCell
                      colSpan={6}
                      className="h-24 text-center text-muted-foreground"
                    >
                      No devices have been named yet. Start with the devices the
                      household will recognize fastest.
                    </TableCell>
                  </TableRow>
                ) : (
                  settings.devices.map((device) => (
                    <TableRow key={device.id}>
                      <TableCell className="font-medium">
                        {device.name}
                      </TableCell>
                      <TableCell className="font-mono text-sm">
                        {device.ip_address}
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant={
                            device.policy_mode === "custom"
                              ? "default"
                              : "secondary"
                          }
                        >
                          {device.policy_mode === "custom"
                            ? "Custom"
                            : "Default"}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        {device.blocklist_profile_override ?? "Default"}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline">
                          {device.protection_override === "bypass"
                            ? "Bypass"
                            : "Active"}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => startDeviceEdit(device)}
                        >
                          Edit
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
