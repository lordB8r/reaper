defmodule SameDayWeb.Router do
  use SameDayWeb, :router

  alias SameDayWeb.Plug.VerifyNurseAccess
  alias SameDayWeb.Plug.VerifyNurseRole
  alias SameDayWeb.Plugs.CurrentDepartment

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_flash
    plug :protect_from_forgery
    plug :put_secure_browser_headers
    plug Hammer.Plug, rate_limit: {"same_day", :timer.minutes(1), :timer.seconds(1)}, by: :ip
  end

  pipeline :api do
    plug :accepts, ["json"]
  end

  pipeline :user_auth do
    plug SameDayWeb.Auth.Pipeline
  end

  pipeline :internal_api_auth do
    # create the token with
    # {:ok, token, _} = SameDayWeb.Guardian.encode_and_sign(%{api: "internal_sameday_api"}, %{"typ" => "access"}, ttl: {100*52, :week})
    # To use from a js console:
    # > token = "<token value from the previous call>"
    # > await (await fetch("http://localhost:4000/api/accounts/test_api_auth", {headers: {"Authorization": `Bearer ${token}`}})).json()

    plug SameDayWeb.Auth.ApiPipeline
    plug SameDayWeb.Plug.VerifyAPIAccess, allowed_access: ["internal_sameday_api"]
  end

  pipeline :business_api_auth do
    plug SameDayWeb.Plug.BusinessAuthentication
  end

  pipeline :halo_api_auth do
    # To authenticate
    # {:ok, token, _claim} = SameDayWeb.Guardian.encode_and_sign(%{api: "halo_api"}, %{"typ" => "access"}, ttl: {100*52, :week})
    plug SameDayWeb.Auth.ApiPipeline
    plug SameDayWeb.Plug.VerifyAPIAccess, allowed_access: ["halo_api"]
  end

  pipeline :provider_auth do
    # routes accessible if user has logged into a "provider" account. All roles are accepted
    plug SameDayWeb.Auth.NursePipeline
    plug CurrentDepartment
    plug VerifyNurseRole, except: [SameDay.Accounts.Nurse.Role.CustomerSupport, SameDay.Accounts.Nurse.Role.BillingSpecialist]
  end

  pipeline :nurse_auth do
    # more restrictive auth for employees and partners of Sameday
    plug SameDayWeb.Auth.NursePipeline
    plug CurrentDepartment
    plug VerifyNurseRole, except: [SameDay.Accounts.Nurse.Role.CustomerSupport, SameDay.Accounts.Nurse.Role.BillingSpecialist]
    plug VerifyNurseAccess, allowed_access: ["admin", "nurse", "lab_director"]
  end

  pipeline :team_auth do
    # used to provide access for supervisors of teams
    plug SameDayWeb.Auth.NursePipeline
    plug CurrentDepartment
    plug VerifyNurseRole, except: [SameDay.Accounts.Nurse.Role.CustomerSupport, SameDay.Accounts.Nurse.Role.BillingSpecialist]
    plug VerifyNurseAccess, allowed_access: ["team", "admin", "nurse"]
  end

  pipeline :admin_auth do
    # used to provide access for admins only
    plug SameDayWeb.Auth.NursePipeline
    plug CurrentDepartment
    plug VerifyNurseRole, except: [SameDay.Accounts.Nurse.Role.CustomerSupport, SameDay.Accounts.Nurse.Role.BillingSpecialist]
    plug VerifyNurseAccess, allowed_access: ["admin"]
  end

  pipeline :portal_admin_auth do
    # used to provide access for portal admins only
    plug SameDayWeb.Auth.NursePipeline
    plug CurrentDepartment
    plug VerifyNurseRole, only: [SameDay.Accounts.Nurse.Role.PortalAdmin]
  end

  pipeline :customer_support_auth do
    # used to provide access for customer support (limited Sameday accounts)
    plug SameDayWeb.Auth.NursePipeline
    plug VerifyNurseRole, only: [SameDay.Accounts.Nurse.Role.CustomerSupport, SameDay.Accounts.Nurse.Role.PortalAdmin]
  end

  pipeline :billing_specialist_auth do
    # used to provide access for billing specialists (may be an external user)
    plug SameDayWeb.Auth.NursePipeline
    plug VerifyNurseRole, only: [SameDay.Accounts.Nurse.Role.BillingSpecialist, SameDay.Accounts.Nurse.Role.PortalAdmin]
  end

  pipeline :ensure_auth do
    plug Guardian.Plug.EnsureAuthenticated
  end

  # OPEN ROUTES - no pipe/guardian auth
  scope "/", SameDayWeb do
    pipe_through :browser

    # Login routes
    get "/login", UserController, :login
    get "/login_confirmed/:email", UserController, :user_login_confirmed  # email sent confirmation page
    get "/verification_code", UserController, :ask_user_for_verification_code
    post "/verification_code", UserController, :verify_user_code
    get "/verify_login/:magic_string", UserController, :verify_login  # verify birthday page
    post "/login/:magic_string", UserController, :try_login  # api: verify the birthday + magic link combo. [REQUIRES :browser plug]
    get "/logout", UserController, :logout  # api: logout. [REQUIRES :browser plug]

    # Nurse login routes
    get "/provider_login", NurseController, :nurse_login # This needs to stay open!
    get "/provider_login_confirm/:email", NurseController, :login_confirm
    get "/nurse_login/:magic_string", NurseController, :verify_magic_link # api: verify magic link [REQUIRES :browser plug]

    # Routes for nurse/provider on site
    get "/link/:code", PageController, :short_link

    get "/authentication_failed", PageController, :authentication_failed

    # Certbot check route
    get "/.well-known/acme-challenge/:file_name", PageController, :ssl_verify_file

    # routes for users
    get "/ticket/:public_id", UserController, :ticket
    get "/consent/:public_id", UserController, :consent_form # show the consent form associated to this public id
    post "/sign_consent_form", UserController, :sign_consent_form # api route to sign the consent form

    get "/test_result_qr_code/:public_id", UserController, :test_result_qr_code

    get "/_internal/status", StatusController, :show
  end

  # protected user resources
  scope "/", SameDayWeb do
    pipe_through [:browser, :user_auth, :ensure_auth]

    get "/", UserController, :home
    get "/results", UserController, :results
    get "/test_result_pdf/:test_result_id/:pdf_name", UserController, :test_result_pdf # pdf_name is aesthetic only but do not remove
    get "/superbill/:test_result_id", UserController, :superbill_pdf
  end

  # protected provider resources
  scope "/", SameDayWeb do
    pipe_through [:browser, :provider_auth, :ensure_auth]
    get "/care", NurseController, :care
    get "/change_department/:department_id", PageController, :change_department
    get "/change_department", PageController, :change_department
  end

  # protected admin/nurse(client manager) resources
  scope "/", SameDayWeb do
    pipe_through [:browser, :nurse_auth, :ensure_auth]

    scope "/client_manager" do
      # test result methods
      post "/test_result/:test_result_id/:department_lab", ClientManagerController, :resubmit_order
      get "/test_results/intake_scan", ClientManagerController, :test_result_intake_scan
      get "/test_results/intake/:barcode_id", ClientManagerController, :test_result_intake
      post "/test_results/intake/finalize", ClientManagerController, :finalize_test_result
    end

    # Nurse intake onsite # Migrate PageController stuff over to NurseController where applicable
    get "/scanner", PageController, :scanner # QR Code intake scanner
    get "/intake/:qr_code_string", NurseController, :intake # Shows patient info
    post "/berry/intake/:appointment_id", NurseController, :berry_intake # Submits the order to Berry

    # https://www.notion.so/sameday/Endpoint-to-open-nurse-intake-view-with-acuity-id-67efd94389594bbbb7a3042269f66c24
    # Technically it's the same view as :intake_qr_code. This is a solution for cases when the public_id is unknown
    # We plan to migrate to another solution later to avoid using acuity ids
    # One possible way is
    # https://www.notion.so/sameday/Notify-frontend-when-appointment-is-created-023fdc8124b6430ab47c3f7779646d76
    get "/intake_acuity_id/:acuity_id", NurseController, :intake_acuity_id

    get "/intake_qr_code/:public_id", NurseController, :intake_qr_code # returns a user's appointment information
    get "/edit_intake/:qr_code_string", NurseController, :edit_intake_form # show form to edit patient info
    get "/health_check/:qr_code_string", NurseController, :health_check
    get "/intake_scan/:qr_code_string", PageController, :intake_scan # Barcode scanner with manual option
    get "/verify_appointment/:qr_code_string", NurseController, :verify_appointment # API Call: retrieve appointment information
    get "/intake_scan_confirm/:qr_code_string/:bar_code_string", PageController, :intake_scan_confirm # Prompt nurse to confirm scan matches
    get "/verify_barcode_scan/:bar_code_string", PageController, :verify_barcode_scan # API call: Ensure barcode is valid from DB and length or prompt user to not allow (an API call via js on front)
    get "/validate_appointment/:qr_code_string", NurseController, :validate_appointment # API Call to ensure that the appointment data is all correct before submitting

    post "/submit_order/:qr_code_string/:bar_code_string", NurseController, :submit_order # API call: final intake, record any relevant data and send order to laboratory
    get "/intake_confirm/:qr_code_string/:bar_code_string", NurseController, :intake_confirm # Final checkin screen for vaccination
    get "/intake_confirm/:qr_code_string/:bar_code_string/:lab_record_id", NurseController, :intake_confirm # Final confirmation/completion screen
    get "/appointments", NurseController, :appointments #  List of all today's appointments QR codes
    get "/dispatcher_appointments", NurseController, :dispatcher_appointments
    get "/recent_appointments", NurseController, :recent_appointments
    get "/ordered_rapid_tests", NurseController, :ordered_rapid_tests
    get "/ordered_diagnostic_tests", NurseController, :ordered_diagnostic_tests

    post "/reject_rapid_test_result/:barcode_id", NurseController, :reject_rapid_test_result
    get "/check_barcode", NurseController, :check_barcode # Pull up data from barcode to ensure was accurately entered
    get "/verify_test_result/:barcode_id", NurseController, :verify_test_result # API Call: retrieve appointment information

    get "/admin_overview/", NurseController, :admin_overview # View state of recent orders
    get "/test_result/:id", NurseController, :test_result
    get "/nurse/superbill/:test_result_id", NurseController, :nurse_superbill
    get "/nurse/rush_fees_receipt/:test_result_id", NurseController, :rush_fees_receipt
    get "/nurse/proof_image/:test_result_id", NurseController, :proof_image

    get "/edit_appointment_insurance/:appointment_id/", EditInsuranceController, :edit_appointment_insurance
    get "/edit_appointment_insurance/:appointment_id/:date_selected", EditInsuranceController, :edit_appointment_insurance
    post "/update_appointment", EditInsuranceController, :update_appointment_insurance

    get "/late_test_results/", NurseController, :late_test_results # orders that have been flagged as being almost late

    get "/admin", PageController, :admin
    get "/nurses/revoke/:nurse_id", PageController, :revoke_nurse

    resources "/nurses", NurseController, only: [:new, :create, :update, :edit]

    resources "/staff", StaffController, only: [:index, :new, :create, :update, :edit]
    get "/staff/:staff_id/qr_code", StaffController, :show_qr_code

    # B2B-related management actions
    scope "/teams", Team, as: :team do
      get "/compliance_notifications", ComplianceNotificationController, :index
      post "/compliance_notifications/:id/claim", ComplianceNotificationController, :claim
      post "/compliance_notifications/:id/finish", ComplianceNotificationController, :finish
    end

    scope "/vaccination_portal" do
      get "/", VaccinationController, :portal
      get "/late_appointments", VaccinationController, :late_appointments
      get "/unfinalized_vaccinations", VaccinationController, :unfinalized_vaccinations
      get "/report_temporary", VaccinationController, :report_temporary

      scope "/vaccination" do
        get "/finalize", VaccinationController, :finalize
        get "/scan_barcode", VaccinationController, :scan_barcode
        get "/vaccine_intake/:barcode_id", VaccinationController, :vaccine_intake
        get "/edit_location/:barcode_id/:current", VaccinationController, :edit_location
        get "/update_location/:barcode_id/:new_department_id", VaccinationController, :update_location
        post "/finalize_vaccination_report", VaccinationController, :finalize_vaccination_report
      end

      scope "/shipments" do
        resources "/", VaccineShipmentController, only: [:index, :new, :create, :edit, :update]
        get "/:id/visible/:new_state", VaccineShipmentController, :change_visibility
      end
    end

    scope "/billing" do
      get "/", NurseController, :billing
      get "/quickmed_insurance_california", NurseController, :quickmed_insurance_california
      get "/download_quickmed_insurance_california/:date", NurseController, :download_quickmed_insurance_california
      get "/quickmed_insurance_virginia", NurseController, :quickmed_insurance_virginia
      get "/download_quickmed_insurance_virginia/:date", NurseController, :download_quickmed_insurance_virginia
      get "/drug_scan", NurseController, :drug_scan_billing
      get "/download_drug_scan/:date", NurseController, :download_drug_scan_billing
      get "/organizations/:organization_id/:test_type", BillingController, :organization_insurance
      get "/organizations/:organization_id/:test_type/:date", BillingController, :download_organization_insurance
      get "/atlantic_insurance", BillingController, :atlantic_insurance
      get "/atlantic_insurance/:date", BillingController, :download_atlantic_insurance
      get "/updated_insurance", BillingController, :updated_insurance
      post "/download_updated_insurance", BillingController, :download_updated_insurance
      get "/vaccinations", NurseController, :vaccinations_billing
      get "/download_vaccinations/:date/:state", NurseController, :download_vaccinations
    end

    # Admin only
    get "/nurses", PageController, :nurses
    get "/set_antigen_type", NurseController, :set_antigen_type
    get "/set_antigen_type/:type", NurseController, :set_antigen_type
    get "/set_lab", NurseController, :set_lab
    get "/set_self_payer_lab/:lab", NurseController, :set_self_payer_lab
    get "/set_priority_insurance_lab/:lab", NurseController, :set_priority_insurance_lab
    get "/set_lab/:lab", NurseController, :set_lab
    resources "/teams", TeamController, only: [:index, :new, :create, :edit, :update]

    # Label generation
    get "/print_barcodes", PageController, :print_barcodes
    get "/download_barcodes", PageController, :download_barcodes

    # Lab director routes
    get "/lab_upload_results", NurseController, :lab_upload_results
    post "/lab_upload_results_submit", NurseController, :lab_upload_results_submit #lab_review_results
    get "/create_test_result_pdf/:test_result_id/:pdf_name", NurseController, :create_test_result_pdf
    post "/approve_lab_results", NurseController, :approve_lab_results
    get "/lab_view_results", NurseController, :lab_view_results
    get "/lab_results_access", NurseController, :lab_results_access
    scope "/lis" do # TODO: LIS, refactor into own controller
      get "/dearchive_pending_order/:test_result_id", LISController, :dearchive_pending_order # Make not archived
      get "/associate_samples_to_plate", LISController, :associate_samples_to_plate
      get "/associate_samples_to_plate/edit/:test_plate_id", LISController, :associate_samples_to_plate_edit
      get "/sample_check/:barcode_id", LISController, :sample_check
      get "/test_plates", LISController, :test_plates
      get "/test_plate/:test_plate_id", LISController, :test_plate
      get "/test_plate_csv/:test_plate_id", LISController, :test_plate_csv
      get "/test_plate_results_csv/:test_plate_id", LISController, :test_plate_results_csv
      get "/manage_accounts", LISController, :manage_accounts
      get "/manage_accounts/new", LISController, :manage_accounts_new
      get "/manage_accounts/revoke/:nurse_id", LISController, :manage_accounts_revoke
      post "/manage_accounts/create", LISController, :manage_accounts_create
      post "/associate_samples_to_plate_submit", LISController, :associate_samples_to_plate_submit
      post "/associate_samples_to_plate_submit_edit/:test_plate_id", LISController, :associate_samples_to_plate_submit_edit
    end

    scope "/lis", LIS, as: :lis do
      resources "/patient-report", PatientReportController, only: [:new, :create]
      resources "/combine-plates", CombinePlatesController, only: [:new, :create]

      scope "/pending_orders" do
        resources "/", PendingOrderController, only: [:index]

        get "/archived", PendingOrderController, :index_archived
        post "/archive", PendingOrderController, :archive
        get "/:test_result_id/finalize_invalid", PendingOrderController, :finalize_invalid
        post "/:test_result_id/finalize_invalid", PendingOrderController, :finalize_invalid
      end
    end

    get "/provider_test_result_pdf/:test_result_id/:pdf_name", NurseController, :test_result_pdf # pdf_name is aesthetic only but do not remove
    get "/provider_requisition_form_pdf/:test_result_id", NurseController, :requisition_form_pdf

    # View Only routes for Franchises, Government, and Other Authorized entities
    get "/ext/test_results", NurseController, :ext_test_results # test results for external access

    scope "/appointment_uploads" do
      get "/", AppointmentUploadController, :index
      post "/submit", AppointmentUploadController, :submit
    end
  end

  scope "/government_reporting", SameDayWeb.GovernmentReporting, as: :government_reporting do
    pipe_through [:browser, :nurse_auth, :ensure_auth]

    get "/", DashboardController, :index

    scope "/co" do
      get "/daily", ColoradoController, :daily
      get "/download/:datetime", ColoradoController, :download
    end

    scope "/ny" do
      scope "/point_of_care" do
        get "/daily", NewYorkController, :point_of_care_daily
        get "/download/:datetime", NewYorkController, :point_of_care_download
      end
      scope "/pcr" do
        get "/daily", NewYorkController, :pcr_daily
        get "/download/:date", NewYorkController, :pcr_download
      end
    end
  end

  scope "/admin", SameDayWeb do
    scope "/consultations" do
      pipe_through [:browser, :admin_auth, :ensure_auth]
      get "/", AdminController, :consultations_menu
      get "/consultation_reports", AdminController, :consultation_reports
      get "/consultation_report/:id", AdminController, :consultation_notes
      get "/consultation_report/:id/report", AdminController, :consultation_report
      get "/positive_test_results_by_day", AdminController, :positive_test_results_by_day
      get "/positive_test_results_by_day/:date", AdminController, :download_positive_test_results_by_day
    end

    scope "/doctors" do
      pipe_through [:browser, :admin_auth, :ensure_auth]

      get "/", AdminController, :manage_doctors
      get "/:doctor_id/state_licenses", AdminController, :show_state_licenses
    end
  end

  # Portal admin endpoints
  scope "/admin", SameDayWeb do
    pipe_through [:browser, :portal_admin_auth, :ensure_auth]

    scope "/departments", Department, as: :department do
      resources "/clia_certificates", CliaCertificateController, only: [:index, :new, :create]
    end

    resources "/departments", DepartmentController, except: [:delete] do
      get "/clia_certificates/new", DepartmentController, :select_new_clia_certificate
      post "/clia_certificates/associate", DepartmentController, :associate_clia_certificate
      delete "/clia_certificates/:id", DepartmentController, :disassociate_clia_certificate

      resources "/calendars", Department.CalendarController, except: [:index, :show]
    end

    scope "/integrations", Integrations, as: :integrations do
      resources "/oauth", OauthDataController, only: [:index], as: :oauth
      get "/oauth/callback", OauthDataController, :callback, as: :oauth
      get "/oauth/refresh", OauthDataController, :refresh, as: :oauth
      get "/oauth/check", OauthDataController, :check, as: :oauth
    end
  end

  # protected team resources
  scope "/", SameDayWeb do
    pipe_through [:browser, :team_auth, :ensure_auth]
    # consent form route is in the open routes directing to appointments
    get "/my_teams", TeamController, :my_teams # overview to see all my teams
    get "/teams/:certificate/results/:id", TeamController, :download_report # download named pdf
    scope "/team" do
      get "/:certificate", TeamController, :team_results # see all results for a given team certificate
      put "/:certificate/cancel/:id", TeamController, :cancel_appointment # cancel an appointment

      get "/:certificate/access/", TeamController, :team_access # Add Nurse (employees) onto teams
      get "/:certificate/access/add", TeamController, :team_access_add # Add Nurse (employees) onto teams form
      post "/:certificate/access/add", TeamController, :team_access_create # Add to team
      get "/:certificate/access/revoke/:nurse_id", TeamController, :team_access_revoke # Remove team member

      get "/:certificate/download", TeamController, :download_results # Bulk download PDFs and potentially CSVs
      post "/:certificate/download", TeamController, :download_results # From posted test result IDs return zip for download
      get "/:certificate/download_csv", TeamController, :download_csv # Download team summary as CSV
    end
  end

  # Customer support portal
  scope "/customer_support", SameDayWeb.CustomerSupport, as: :customer_support do
    pipe_through [:browser, :customer_support_auth, :ensure_auth]

    get "/", DashboardController, :index

    resources "/test_results", TestResultController, only: [:index]
    get "/test_results/:test_result_id/download", TestResultController, :download
    get "/test_results/:test_result_id/send_by_email", TestResultController, :send_by_email

    resources "/users", UserController, only: [:index, :update]

    get "/refunds/appointment", RefundController, :index
    get "/refunds/appointment/:squarespace_id/refund_confirm", RefundController, :refund_confirm
    post "/refunds/appointment/:squarespace_id/post_refund", RefundController, :post_refund
  end

  # Billing Specialist portal
  scope "/billing_specialist", SameDayWeb.BillingSpecialist, as: :billing_specialist do
    pipe_through [:browser, :billing_specialist_auth, :ensure_auth]

    get "/", DashboardController, :index

    resources "/patients", PatientController, only: [:index]
    get "/patients/:patient_identifier/details", PatientController, :details
    get "/patients/:patient_identifier/appointment/:appointment_id/download", PatientController, :download_insurance
    get "/patients/:patient_identifier/test_results/:test_result_id/requisition_form", PatientController, :test_result_requisition_form
    get "/patients/:patient_identifier/test_results/:test_result_id/report", PatientController, :test_result_report
  end

  # Protected API access for nurses
  scope "/api", SameDayWeb do
    # uses :browser because guardian fails when only using :api
    pipe_through [:api, :browser, :nurse_auth, :ensure_auth]

    post "/appointment/update", NurseController, :update_appointment # update triggered by client manager
  end

  # Open API (the LIS part requires authentication)
  scope "/api", SameDayWeb do
    pipe_through :api

    # Login API
    post "/initiate_login", UserController, :initiate_login
    post "/initiate_nurse_login", NurseController, :initiate_nurse_login

    # acuity web hook
    post "/update_appointment", AcuityController, :create_or_update_appointment

    scope "/lis", API.LIS, as: :api_lis do
      pipe_through :halo_api_auth

      resources "/orders", OrderController, only: [:create, :show], as: :order, param: "sample_id"
      get "/orders/:sample_id/pdf", OrderController, :pdf
    end

    scope "/berry", API.Berry, as: :api_berry do
      pipe_through :halo_api_auth

      resources "/webhook", WebhookController, only: [:create], singleton: true
    end
  end

  # Authenticated API Only
  scope "/api", SameDayWeb do
    scope "/" do
      pipe_through :internal_api_auth

      scope "/accounts" do
        get "/test_api_auth", APIController, :test_api_auth

        get "/:email/password_exists", APIController, :check_password_exists
        post "/:email/check_password", APIController, :check_password
        post "/:email/set_password", APIController, :set_password

        get "/:email", APIController, :get_account
        get "/:email/patients/", APIController, :get_patients
        get "/:email/test_results", APIController, :get_test_results
        get "/:email/vaccinations", APIController, :get_vaccinations
        get "/:email/appointments", APIController, :get_appointments

        get "/:email/test_result_pdf/:test_result_id", APIController, :test_result_pdf
        get "/:email/superbill_pdf/:public_appointment_id", APIController, :superbill_pdf
      end

      scope "/appointments" do
        get "/:public_id", APIController, :get_appointment_by_public_id
        get "/acuity_id/:acuity_id", APIController, :get_appointment_by_acuity_id
      end

      scope "/business/:nurse_email", Business, as: :business do
        pipe_through :business_api_auth

        resources "/projects", ProjectController, only: [:index]
      end

      scope "/ehr", API.EHR, as: :ehr do
        resources "/appointment_templates", AppointmentTemplatesController, only: [:index]
        resources "/offices", OfficesController, only: [:index]
        resources "/patients", PatientsController, only: [:index, :create]
        resources "/telehealth_appointments", TelehealthAppointmentsController, only: [:index, :create]
      end

      scope "/nurse" do
        # To support a web view from an iOS app without additional login process
        # (iOS app will be responsible for the nurse auth)
        get "/:email/issue_token", APIController, :issue_nurse_token
      end

      scope "/nurses" do
        get "/:email", API.NurseController, :show
        post "/:email/appointments", APIController, :get_department_appointments
        get "/:email/magic-link", API.NurseController, :magic_link
      end

      scope "/integrations" do
        scope "/oauth" do
          get "/token", Integrations.OauthDataController, :token
        end
      end
    end
  end

  if Application.get_env(:same_day, SameDay.Mailer)[:adapter] == Swoosh.Adapters.Local do
    forward "/dev/mailbox", Plug.Swoosh.MailboxPreview
  end
end
