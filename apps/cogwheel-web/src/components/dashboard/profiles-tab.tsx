import { useEffect, useState } from "react";
import { Plus, X } from "lucide-react";
import { useCogwheel } from "@/contexts/cogwheel-context";
import { emptyBlockProfileDraft, oisdProfileOptions } from "@/lib/constants";
import { cn } from "@/lib/utils";
import type { BlockProfileListRecord, BlockProfileRecord } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

export function ProfilesTab() {
  const {
    settings,
    busyAction,
    pushToast,
    handleBlockProfileSave,
    handleBlockProfileDelete,
  } = useCogwheel();

  const [selectedProfileId, setSelectedProfileId] = useState<string | null>(
    null,
  );
  const [creating, setCreating] = useState(false);
  const [draft, setDraft] = useState<BlockProfileRecord>({
    ...emptyBlockProfileDraft,
    updated_at: new Date().toISOString(),
  });
  const [allowlistDraft, setAllowlistDraft] = useState("");
  const [customListName, setCustomListName] = useState("");
  const [customListUrl, setCustomListUrl] = useState("");

  // Keep the draft in sync when the profile list changes
  useEffect(() => {
    const selected = settings.block_profiles.find(
      (p) => p.id === selectedProfileId,
    );
    if (selected) {
      setCreating(false);
      setDraft(selected);
      setAllowlistDraft(selected.allowlists.join(", "));
      return;
    }

    if (creating) return;

    if (settings.block_profiles.length > 0 && selectedProfileId === null) {
      const first = settings.block_profiles[0];
      setSelectedProfileId(first.id);
      setDraft(first);
      setAllowlistDraft(first.allowlists.join(", "));
      return;
    }

    if (settings.block_profiles.length === 0) {
      setDraft({ ...emptyBlockProfileDraft, updated_at: new Date().toISOString() });
      setAllowlistDraft("");
    }
  }, [creating, selectedProfileId, settings.block_profiles]);

  // ------- Actions -------

  function startNewBlockProfile() {
    setCreating(true);
    setSelectedProfileId(null);
    setDraft({ ...emptyBlockProfileDraft, updated_at: new Date().toISOString() });
    setAllowlistDraft("");
    setCustomListName("");
    setCustomListUrl("");
  }

  function selectProfile(profile: BlockProfileRecord) {
    setCreating(false);
    setSelectedProfileId(profile.id);
    setDraft(profile);
    setAllowlistDraft(profile.allowlists.join(", "));
    setCustomListName("");
    setCustomListUrl("");
  }

  function togglePreset(option: BlockProfileListRecord) {
    setDraft((prev) => {
      const exists = prev.blocklists.some((e) => e.id === option.id);
      if (exists) {
        return { ...prev, blocklists: prev.blocklists.filter((e) => e.id !== option.id) };
      }
      let next = prev.blocklists.filter((e) => {
        if (option.id === "oisd-big") return e.id !== "oisd-small";
        if (option.id === "oisd-small") return e.id !== "oisd-big";
        if (option.id === "oisd-nsfw") return e.id !== "oisd-nsfw-small";
        if (option.id === "oisd-nsfw-small") return e.id !== "oisd-nsfw";
        return true;
      });
      next = [...next, option].sort((a, b) => a.name.localeCompare(b.name));
      return { ...prev, blocklists: next };
    });
  }

  function addCustomList() {
    const name = customListName.trim();
    const url = customListUrl.trim();
    if (!name || !url) {
      pushToast("List details required", "Enter both a list name and a GitHub URL before adding it.", "error");
      return;
    }
    if (!(url.includes("github.com") || url.includes("raw.githubusercontent.com"))) {
      pushToast("GitHub URL required", "Manual lists should point at a GitHub or raw GitHub blocklist URL.", "error");
      return;
    }
    const entry: BlockProfileListRecord = {
      id: name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") || `custom-${Date.now()}`,
      name,
      url,
      kind: "custom",
      family: "custom",
    };
    setDraft((prev) => ({
      ...prev,
      blocklists: [...prev.blocklists.filter((e) => e.url !== url), entry].sort((a, b) =>
        a.name.localeCompare(b.name),
      ),
    }));
    setCustomListName("");
    setCustomListUrl("");
  }

  function removeList(id: string) {
    setDraft((prev) => ({ ...prev, blocklists: prev.blocklists.filter((e) => e.id !== id) }));
  }

  async function handleSave() {
    if (!draft.name.trim()) {
      pushToast("Name required", "Give the block profile a friendly name before saving.", "error");
      return;
    }
    await handleBlockProfileSave(draft, allowlistDraft);
    setCreating(false);
  }

  async function handleDelete() {
    if (!selectedProfileId) {
      pushToast("Profile required", "Choose a saved profile before deleting it.", "error");
      return;
    }
    await handleBlockProfileDelete(selectedProfileId, draft.name || "This profile");
  }

  // ------- Render -------

  const editing = !!selectedProfileId;

  return (
    <div className="p-4 md:p-6 space-y-4">
      <div className="grid gap-6 xl:grid-cols-[360px_minmax(0,1fr)]">
        {/* -- Left Column: Profile Library -- */}
        <Card>
          <CardHeader>
            <CardTitle>Profiles</CardTitle>
            <CardDescription>
              Manage block profiles for different devices and routines
            </CardDescription>
            <CardAction>
              <Button variant="outline" size="sm" onClick={startNewBlockProfile}>
                <Plus className="size-4" />
                New
              </Button>
            </CardAction>
          </CardHeader>
          <CardContent>
            {settings.block_profiles.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                No saved profiles yet. Create one to get started.
              </p>
            ) : (
              <div className="space-y-2">
                {settings.block_profiles.map((p) => {
                  const isActive = selectedProfileId === p.id && !creating;
                  return (
                    <button
                      key={p.id}
                      type="button"
                      onClick={() => selectProfile(p)}
                      className={cn(
                        "w-full rounded-lg border p-3 text-left transition-colors",
                        isActive
                          ? "border-primary bg-primary/5"
                          : "hover:bg-muted/50",
                      )}
                    >
                      <div className="flex items-center justify-between">
                        <div>
                          <span className="mr-2">{p.emoji || "\u25CC"}</span>
                          <span className="font-medium">{p.name}</span>
                        </div>
                        <Badge variant="secondary">
                          {p.blocklists.length} sources
                        </Badge>
                      </div>
                      {p.description && (
                        <p className="mt-1 text-sm text-muted-foreground">
                          {p.description}
                        </p>
                      )}
                    </button>
                  );
                })}
              </div>
            )}
          </CardContent>
        </Card>

        {/* -- Right Column: Profile Editor -- */}
        <Card>
          <CardHeader>
            <CardTitle>{editing ? "Edit Profile" : "New Profile"}</CardTitle>
            <CardDescription>
              Configure identity, blocklist sources, and allowlist exceptions
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            {/* Identity */}
            <div className="space-y-3">
              <Label>Profile Identity</Label>
              <div className="grid gap-3 sm:grid-cols-[100px_1fr]">
                <Input
                  value={draft.emoji}
                  onChange={(e) =>
                    setDraft((prev) => ({ ...prev, emoji: e.target.value }))
                  }
                  placeholder="Emoji"
                />
                <Input
                  value={draft.name}
                  onChange={(e) =>
                    setDraft((prev) => ({ ...prev, name: e.target.value }))
                  }
                  placeholder="Profile name"
                />
              </div>
              <Input
                value={draft.description}
                onChange={(e) =>
                  setDraft((prev) => ({ ...prev, description: e.target.value }))
                }
                placeholder="Description"
              />
            </div>

            <Separator />

            {/* OISD Presets */}
            <div className="space-y-3">
              <Label>OISD Blocklist Presets</Label>
              <p className="text-sm text-muted-foreground">
                Core and NSFW families are kept mutually exclusive automatically.
              </p>
              <div className="grid gap-3 lg:grid-cols-2">
                {oisdProfileOptions.map((option) => {
                  const enabled = draft.blocklists.some(
                    (e) => e.id === option.id,
                  );
                  return (
                    <button
                      key={option.id}
                      type="button"
                      onClick={() => togglePreset(option)}
                      className={cn(
                        "rounded-lg border p-3 text-left text-sm transition-colors",
                        enabled
                          ? "border-primary bg-primary/5"
                          : "hover:bg-muted/50",
                      )}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-medium">{option.name}</span>
                        <Badge variant={enabled ? "default" : "secondary"}>
                          {option.id.includes("small") ? "small" : "full"}
                        </Badge>
                      </div>
                      <p className="mt-1 text-xs text-muted-foreground">
                        {option.id.includes("nsfw")
                          ? "Adult-content focused OISD feed."
                          : "General-purpose OISD protection feed."}
                      </p>
                    </button>
                  );
                })}
              </div>
            </div>

            <Separator />

            {/* Custom Lists */}
            <div className="space-y-3">
              <Label>Custom GitHub Lists</Label>
              <div className="grid gap-3 lg:grid-cols-[0.85fr_1.15fr_auto]">
                <Input
                  value={customListName}
                  onChange={(e) => setCustomListName(e.target.value)}
                  placeholder="List name"
                />
                <Input
                  value={customListUrl}
                  onChange={(e) => setCustomListUrl(e.target.value)}
                  placeholder="https://raw.githubusercontent.com/.../domains.txt"
                />
                <Button variant="secondary" onClick={addCustomList}>
                  Add list
                </Button>
              </div>
            </div>

            <Separator />

            {/* Allowlist */}
            <div className="space-y-3">
              <Label>Allowlist Exceptions</Label>
              <p className="text-sm text-muted-foreground">
                Comma-separated domains that should stay reachable even when blocked
                by a selected list.
              </p>
              <Input
                value={allowlistDraft}
                onChange={(e) => setAllowlistDraft(e.target.value)}
                placeholder="school.example, video.example"
              />
            </div>

            <Separator />

            {/* Active Sources Table */}
            <div className="space-y-3">
              <Label>Active Sources</Label>
              {draft.blocklists.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  Choose at least one OISD preset or add a custom GitHub list.
                </p>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Name</TableHead>
                      <TableHead>URL</TableHead>
                      <TableHead>Kind</TableHead>
                      <TableHead className="w-[1%]" />
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {draft.blocklists.map((list) => (
                      <TableRow key={list.id}>
                        <TableCell className="font-medium">
                          {list.name}
                        </TableCell>
                        <TableCell className="max-w-[300px] truncate text-muted-foreground">
                          {list.url}
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline">{list.kind}</Badge>
                        </TableCell>
                        <TableCell>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="size-7"
                            onClick={() => removeList(list.id)}
                          >
                            <X className="size-3.5" />
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </div>
          </CardContent>
          <CardFooter className="justify-end gap-2">
            {editing && (
              <Button
                variant="outline"
                onClick={() => void handleDelete()}
                disabled={busyAction === "block-profile-delete"}
              >
                {busyAction === "block-profile-delete" ? "Deleting..." : "Delete"}
              </Button>
            )}
            <Button
              onClick={() => void handleSave()}
              disabled={busyAction === "block-profile-save"}
            >
              {busyAction === "block-profile-save" ? "Saving..." : "Save Profile"}
            </Button>
          </CardFooter>
        </Card>
      </div>
    </div>
  );
}
