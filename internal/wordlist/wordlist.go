// Package wordlist holds the candidate names used when a server does not
// expose reflection and no descriptor is available.
//
// The lists are deliberately small and shaped like real Go/gRPC service
// names. They are a starting point, not an exhaustive dictionary: guessing is
// the weakest enumeration source, and the report labels anything found this
// way as "guessed" until the existence oracle corroborates it.
package wordlist

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// DefaultServices is a wordlist of gRPC service names as they appear in path
// segments (sans package). Each entry is expanded by the scanner across the
// packages it detects or supplies.
var DefaultServices = []string{
	// generic backends
	"UserService", "UsersService", "AccountService", "AuthService", "AuthenticationService",
	"SessionService", "OrderService", "OrdersService", "PaymentService", "ProductService",
	"CatalogService", "InventoryService", "CartService", "CheckoutService", "NotificationService",
	"MessageService", "MailService", "EmailService", "SMSService", "SearchService",
	"FileService", "StorageService", "UploadService", "MediaService", "ImageService",
	"ReportService", "AnalyticsService", "MetricsService", "StatisticsService", "AuditService",
	"LogService", "LoggingService", "EventService", "WebhookService", "GatewayService",
	"ProxyService", "RoutingService", "LocationService", "GeoService", "DeviceService",
	"TenantService", "WorkspaceService", "TeamService", "ProjectService", "TaskService",
	"JobService", "SchedulerService", "WorkflowService", "QueueService", "StreamService",
	"CommentService", "FeedService", "SocialService", "ProfileService", "IdentityService",
	"PermissionService", "RoleService", "PolicyService", "TokenService", "KeyService"}

// AdminServices are management-flavoured names. They are the ones most likely
// to carry the incident's actual risk: cache control, config writes, drains.
var AdminServices = []string{
	"AdminService", "Admin", "ManagementService", "ManageService", "InternalService",
	"OpsService", "OperationService", "SystemService", "DebugService", "DiagnosticService",
	"MaintenanceService", "ControlService", "ControlPlaneService", "ConfigService",
	"ConfigurationService", "MetaService", "ClusterService", "NodeService", "ShardService",
	"ReplicaService", "HealthAdminService", "ConsoleService", "CommandService",
	"ExecutorService", "AgentService", "SupervisorService", "GovernanceService",
	"InfraService", "PlatformService", "BootstrapService", "MigrationService",
	"CacheAdminService", "CacheService", "QueueAdminService", "IndexAdminService",
	"TenantAdminService", "UserAdminService", "RoleAdminService", "AuditAdminService"}

// DefaultMethods is a wordlist of method names, weighted toward the
// state-changing management calls that make an exposed service dangerous.
var DefaultMethods = []string{
	// management and state-changing
	"FlushCache", "ClearCache", "PurgeCache", "InvalidateCache", "ResetCache", "ReloadConfig",
	"UpdateConfig", "SetConfig", "ApplyConfig", "Reload", "Restart", "Shutdown", "Stop",
	"Drain", "Evict", "Invalidate", "Refresh", "Resync", "Rebuild", "Rebalance",
	"Delete", "DeleteAll", "Purge", "Drop", "Truncate", "Remove", "Reset", "Wipe",
	"Create", "Update", "Upsert", "Patch", "Set", "Put", "Write", "Import", "Upload",
	"Register", "Unregister", "Enable", "Disable", "Grant", "Revoke", "Assign",
	"Run", "Execute", "Exec", "Invoke", "Trigger", "Schedule", "Submit", "Publish",
	"Migrate", "Rollback", "Deploy", "Provision", "Scale", "Failover", "Promote",
	"Kill", "Terminate", "Cancel", "DrainQueue", "Pause", "Resume", "Suspend",
	"Admin", "Debug", "Dump", "Snapshot", "Backup", "Restore",
	// read-only, useful for confirming the service is real
	"Get", "List", "Find", "Query", "Search", "Lookup", "Describe", "Show", "Read",
	"GetStatus", "GetInfo", "GetVersion", "Version", "Ping", "Echo", "Health", "HealthCheck",
	"WhoAmI", "Whoami", "Check", "Exists", "Count", "Stats", "GetStats", "GetMetrics",
	"GetConfig", "ListServices", "ListUsers", "GetUser", "GetUsers", "ListNodes",
	"GetNode", "ListTenants", "GetTenant", "Watch", "Stream", "Subscribe"}

// Packages are the package prefixes guessed when no descriptors tell us what a
// service's package is. A path segment is "/pkg.Service/Method", so the guess
// is "<package>.<ServiceName>".
var Packages = []string{
	"", // bare service, as when the service has no package
	"api", "v1", "api.v1", "proto", "protos", "pb", "grpc", "rpc", "internal",
	"internal.api", "internal.v1", "backend", "server", "service", "services",
	"admin", "admin.v1", "management", "system", "ops", "platform", "infra",
}

// LoadFile reads a newline-delimited list, ignoring blanks and #-comments.
func LoadFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read wordlist %q: %w", path, err)
	}
	defer f.Close()

	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Allow inline comments.
		if i := strings.Index(line, " #"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		out = append(out, line)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read wordlist %q: %w", path, err)
	}
	return out, nil
}

// LoadFiles loads and de-duplicates several wordlist files.
func LoadFiles(paths []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, p := range paths {
		list, err := LoadFile(p)
		if err != nil {
			return nil, err
		}
		for _, s := range list {
			if seen[s] {
				continue
			}
			seen[s] = true
			out = append(out, s)
		}
	}
	return out, nil
}

// Union combines several slices, keeping the first occurrence of each value.
func Union(lists ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range lists {
		for _, s := range l {
			if seen[s] {
				continue
			}
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
