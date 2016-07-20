#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <list.h>
#include <mem.h>
#include <kadnet.h>
#include <log.h>

#include <wx/wxprec.h>

#ifndef WX_PRECOMP

#include <wx/wx.h>

#endif

#include <wx/listctrl.h>
#include <wx/notebook.h>

typedef struct _file_info {
  uint8_t file_id[16];
  char* file_name;
  uint64_t file_size;
  char buf[1];
} FILE_INFO;

class Kad: public wxApp
{
  public:
    virtual bool OnInit();

};

class MainWnd: public wxFrame
{
  public:
    MainWnd(const wxString& title, const wxPoint& pos, const wxSize& size);
    ~MainWnd();

  private:
    void CreateTB();
    void CreateListView();
    void CreateSearchPanel(wxNotebook* book);
    void CreateDownloadUploadPanel(wxNotebook* book);
    void OnExit(wxCommandEvent& event);
    void OnStartToolClick(wxCommandEvent& event);
    void OnStopToolClick(wxCommandEvent& event);
    void OnSearchClick(wxCommandEvent& event);
    void OnTimer(wxTimerEvent& event);
    void OnSearchResultActivated(wxListEvent& event);
    void UpdateStatus();
    void RefreshSearchResults();

    wxNotebook* m_book;
    wxBoxSizer* m_status_sizer;
    wxPanel* m_status_panel;
    wxToolBar* m_toolbar;
    wxListCtrl* m_listview;
    wxListCtrl* m_search_results;
    wxTimer* m_timer;
    wxTextCtrl* m_search_text;
    wxButton* m_search_start;

    KADNET* m_kn;
    bool m_kn_running;
    bool m_kn_search_running;
    LIST* m_search_results_data;

    wxDECLARE_EVENT_TABLE();
        
};

const int ID_TOOLBAR = 500;

const int ID_TB_START = 501;

const int ID_TB_STOP = 502;

const int ID_UPDATE_TIMER = 600;

const int ID_BOOK = 700;

const int ID_BTN_SEARCH = 800;

const int ID_TXT_SEARCH = 900;

const int ID_RESULTS_LIST = 1000;

wxBEGIN_EVENT_TABLE(MainWnd, wxFrame)
  EVT_MENU(ID_TB_START, MainWnd::OnStartToolClick)
  EVT_MENU(ID_TB_STOP, MainWnd::OnStopToolClick)
  EVT_MENU(wxID_EXIT, MainWnd::OnExit)
  EVT_TIMER(ID_UPDATE_TIMER, MainWnd::OnTimer)
  EVT_BUTTON(ID_BTN_SEARCH, MainWnd::OnSearchClick)
  EVT_TEXT_ENTER(ID_TXT_SEARCH, MainWnd::OnSearchClick)
  EVT_LIST_ITEM_ACTIVATED(ID_RESULTS_LIST, MainWnd::OnSearchResultActivated)
wxEND_EVENT_TABLE()

wxIMPLEMENT_APP(Kad);

bool Kad::OnInit()
{

  MainWnd* wnd = new MainWnd("WxKad", wxPoint(50, 50), wxSize(1020, 480));

  wnd->Show(true);

  return true;

}

MainWnd::MainWnd(const wxString& title, const wxPoint& pos, const wxSize& size):
          wxFrame(NULL, wxID_ANY, title, pos, size)
{

  m_search_results_data = NULL;

  m_book = new wxNotebook(this, ID_BOOK);

  // Status panel

  m_status_sizer = new wxBoxSizer(wxVERTICAL);

  m_status_panel = new wxPanel(m_book, wxID_ANY);

  m_book->AddPage(m_status_panel, "Status");

  CreateListView();
 
  m_status_sizer->Add(m_listview, 1, wxEXPAND | wxALL, 0);

  m_status_panel->SetSizer(m_status_sizer);

  // Search panel
 
  CreateSearchPanel(m_book);

  CreateDownloadUploadPanel(m_book);
  
  wxMenu* menu = new wxMenu();

  menu->Append(ID_TB_START, "&Start Kad\tCtrl-S", "Start Kad client");

  menu->Append(ID_TB_STOP, "S&top Kad\tCtrl-W", "Stop Kad client");

  menu->Append(wxID_EXIT);

  wxMenuBar* menuBar = new wxMenuBar();

  menuBar->Append(menu, "&Menu");

  SetMenuBar(menuBar);

  CreateTB();

  CreateStatusBar();

  SetStatusText("Kad is not running");

  kadnet_init(&m_kn);

  m_kn_running = false;

  m_kn_search_running = false;
 
  m_timer = new wxTimer(this, ID_UPDATE_TIMER);

  m_timer->Start(500);

}

void MainWnd::OnTimer(wxTimerEvent& event)
{

  if (m_kn_running) UpdateStatus();

  if (m_kn_search_running && kadnet_is_keyword_search_finished(m_kn)){

    m_kn_search_running = false;

    RefreshSearchResults();

    m_search_start->Enable();

    m_search_text->Enable();

  }

}

MainWnd::~MainWnd()
{

  m_timer->Stop();

  kadnet_uninit(m_kn);
}

void
MainWnd::CreateTB()
{

  m_toolbar = CreateToolBar(wxTB_TOP | wxTB_NOICONS, ID_TOOLBAR);  

  m_toolbar->AddTool(ID_TB_START, "Start", wxNullBitmap);

  m_toolbar->AddTool(ID_TB_STOP, "Stop", wxNullBitmap);

  m_toolbar->Realize();

}

void MainWnd::OnSearchClick(wxCommandEvent& event)
{
  wxString st = m_search_text->GetValue(); 

  m_search_results->DeleteAllItems();

  kadnet_search_keyword(m_kn, st.ToAscii());

  m_search_start->Disable();

  m_search_text->Disable();

  m_kn_search_running = true;

}

void MainWnd::OnStartToolClick(wxCommandEvent& event)
{

  if (!m_kn_running){

    kadnet_start(m_kn);

    m_kn_running = true;

    SetStatusText("Kad is running");

  }
}

void MainWnd::OnStopToolClick(wxCommandEvent& event)
{

  if (m_kn_running){

    kadnet_stop(m_kn);

    m_kn_running = false;

    SetStatusText("Kad is not running");

  }

}

void MainWnd::OnExit(wxCommandEvent& event)
{

  if (m_kn_running) kadnet_stop(m_kn);
  
  list_destroy(m_search_results_data, TRUE);

  m_search_results_data = NULL;

  Close(true);

}

void MainWnd::CreateListView()
{
  wxListItem itemCol;

  m_listview = new wxListCtrl(
                              m_status_panel, 
                              wxID_ANY, 
                              wxDefaultPosition,
                              wxDefaultSize,
                              wxLC_REPORT | wxBORDER_THEME,
                              wxDefaultValidator,
                              wxListCtrlNameStr
                             );

  itemCol.SetText("Name");

  itemCol.SetImage(-1);

  itemCol.SetAlign(wxLIST_FORMAT_LEFT);

  m_listview->InsertColumn(0, itemCol);

  itemCol.SetText("Value");

  itemCol.SetImage(-1);

  itemCol.SetAlign(wxLIST_FORMAT_CENTRE);

  m_listview->InsertColumn(1, itemCol);

  m_listview->SetColumnWidth(0, wxLIST_AUTOSIZE);

  m_listview->SetColumnWidth(1, wxLIST_AUTOSIZE);

  m_listview->Show();

}

void MainWnd::CreateSearchPanel(wxNotebook* book)
{

  wxPanel* panel = new wxPanel(book, wxID_ANY);

  wxBoxSizer* sizer = new wxBoxSizer(wxVERTICAL);

  // Search text

  wxTextCtrl* tc = new wxTextCtrl(
                                  panel, 
                                  ID_TXT_SEARCH, 
                                  wxEmptyString, 
                                  wxDefaultPosition,
                                  wxDefaultSize,
                                  wxTE_PROCESS_ENTER
                                 );

  m_search_text = tc;

  sizer->Add(tc, 0, wxEXPAND | wxALIGN_RIGHT, 0);

  // Search button
  
  wxButton* btn = new wxButton(
                               panel,
                               ID_BTN_SEARCH,
                               "Search"
                              );

  m_search_start = btn;

  sizer->Add(btn, 0, wxEXPAND, 0);

  // Results list 
  
  wxListItem itemCol;

  wxListCtrl* lc = new wxListCtrl(
                                  panel, 
                                  ID_RESULTS_LIST, 
                                  wxDefaultPosition,
                                  wxDefaultSize,
                                  wxLC_REPORT | wxBORDER_THEME,
                                  wxDefaultValidator,
                                  wxListCtrlNameStr
                                 );

  m_search_results = lc;

  itemCol.SetText("Name");

  itemCol.SetImage(-1);

  itemCol.SetAlign(wxLIST_FORMAT_CENTRE);

  lc->InsertColumn(0, itemCol);

  itemCol.SetText("Size");

  itemCol.SetImage(-1);

  itemCol.SetAlign(wxLIST_FORMAT_CENTRE);

  lc->InsertColumn(1, itemCol);

  itemCol.SetText("Type");

  itemCol.SetImage(-1);

  itemCol.SetAlign(wxLIST_FORMAT_CENTRE);

  lc->InsertColumn(2, itemCol);

  itemCol.SetText("Avail");

  itemCol.SetImage(-1);

  itemCol.SetAlign(wxLIST_FORMAT_CENTRE);

  lc->InsertColumn(3, itemCol);

  lc->SetColumnWidth(0, wxLIST_AUTOSIZE);

  lc->SetColumnWidth(1, wxLIST_AUTOSIZE);

  lc->SetColumnWidth(2, wxLIST_AUTOSIZE);

  lc->SetColumnWidth(3, wxLIST_AUTOSIZE);

  lc->Show();

  sizer->Add(lc, 1, wxEXPAND | wxALL, 0);

  panel->SetSizer(sizer);

  book->AddPage(panel, "Search");

}

void MainWnd::UpdateStatus()
{
  KADNET_STATUS kns;
  wxString str;
  struct in_addr in;

  kadnet_get_status(m_kn, &kns);

  m_listview->DeleteAllItems();

  // Local ip

  in.s_addr = kns.loc_ip4_no;

  inet_ntoa(in);

  long item = m_listview->InsertItem(0, "Local ip", 0);

  m_listview->SetItem(item, 1, wxString::FromAscii(inet_ntoa(in)));
  
  // Public ip

  in.s_addr = kns.pub_ip4_no;

  inet_ntoa(in);

  item = m_listview->InsertItem(1, "Public ip", 0);

  m_listview->SetItem(item, 1, wxString::FromAscii(inet_ntoa(in)));

  // Nodes count

  item = m_listview->InsertItem(2, "Nodes count", 0);

  str.Printf("%d", kns.node_count);

  m_listview->SetItem(item, 1, str);
   
  // Tcp port

  item = m_listview->InsertItem(3, "Tcp port", 0);

  str.Printf("%d", ntohs(kns.tcp_port_no));

  m_listview->SetItem(item, 1, str);

  // Internal udp port

  item = m_listview->InsertItem(4, "Internal udp port", 0);

  str.Printf("%d", ntohs(kns.int_udp_port_no));

  m_listview->SetItem(item, 1, str);

  // External udp port

  item = m_listview->InsertItem(5, "External udp port", 0);

  str.Printf("%d", ntohs(kns.ext_udp_port_no));

  m_listview->SetItem(item, 1, str);
  
  // Tcp firewalled

  item = m_listview->InsertItem(6, "Tcp firewalled", 0);

  m_listview->SetItem(item, 1, kns.tcp_firewalled?"true":"false");

  m_listview->SetColumnWidth(0, wxLIST_AUTOSIZE);

  m_listview->SetColumnWidth(1, wxLIST_AUTOSIZE);
  //
  // Udp firewalled

  item = m_listview->InsertItem(7, "Udp firewalled", 0);

  m_listview->SetItem(item, 1, kns.udp_firewalled?"true":"false");

  m_listview->SetColumnWidth(0, wxLIST_AUTOSIZE);

  m_listview->SetColumnWidth(1, wxLIST_AUTOSIZE);

}

void MainWnd::RefreshSearchResults()
{
  KADNET_SEARCH_RESULT_KEYWORD* ksrk = NULL;
  long item;
  wxString str;
  int i = 0;
  uint8_t* data = NULL;
  FILE_INFO* fi = NULL;
  char* p = NULL;

  list_destroy(m_search_results_data, TRUE);

  m_search_results_data = NULL;

  m_search_results->DeleteAllItems();

  while (kadnet_get_keyword_result(m_kn, &ksrk)){

    item = m_search_results->InsertItem(i++, wxString::FromUTF8(ksrk->file_name), 0);

    do {

      fi = (FILE_INFO*)mem_alloc(sizeof (FILE_INFO) - 1 + strlen(ksrk->file_name) + 1);

      if (!fi) {

        LOG_ERROR((char*)"Failed to allocate memory for file info structure.");

        break;
        
      }

      p = (char*)fi + sizeof(FILE_INFO) - 1;

      fi->file_name = p;

      strcpy(p, ksrk->file_name);

      fi->file_size = ksrk->file_size;

      memcpy(fi->file_id, ksrk->file_id, sizeof(fi->file_id));

      m_search_results->SetItemData(item, (long)fi);

      list_add_entry(&m_search_results_data, fi);

    } while(false);

    str.Printf("%lu", ksrk->file_size);

    m_search_results->SetItem(item, 1, str);

    m_search_results->SetItem(item, 2, wxString::FromUTF8(ksrk->file_type));

    str.Printf("%d", ksrk->avail);

    m_search_results->SetItem(item, 3, str);

  }

  m_search_results->SetColumnWidth(0, wxLIST_AUTOSIZE);

  m_search_results->SetColumnWidth(1, wxLIST_AUTOSIZE);

  m_search_results->SetColumnWidth(2, wxLIST_AUTOSIZE);

  m_search_results->SetColumnWidth(3, wxLIST_AUTOSIZE);

}

void MainWnd::CreateDownloadUploadPanel(wxNotebook* book)
{

  wxPanel* panel = new wxPanel(book, wxID_ANY);

  wxBoxSizer* sizer = new wxBoxSizer(wxVERTICAL);

  // Results list 
  
  wxListItem itemCol;

  wxListCtrl* lc = new wxListCtrl(
                                  panel, 
                                  ID_RESULTS_LIST, 
                                  wxDefaultPosition,
                                  wxDefaultSize,
                                  wxLC_REPORT | wxBORDER_THEME,
                                  wxDefaultValidator,
                                  wxListCtrlNameStr
                                 );

  //m_search_results = lc; [TODO] should be class var for this control

  itemCol.SetText("Name");

  itemCol.SetImage(-1);

  itemCol.SetAlign(wxLIST_FORMAT_CENTRE);

  lc->InsertColumn(0, itemCol);

  itemCol.SetText("Size");

  itemCol.SetImage(-1);

  itemCol.SetAlign(wxLIST_FORMAT_CENTRE);

  lc->InsertColumn(1, itemCol);

  itemCol.SetText("Type");

  itemCol.SetImage(-1);

  itemCol.SetAlign(wxLIST_FORMAT_CENTRE);

  lc->InsertColumn(2, itemCol);

  itemCol.SetText("Avail");

  itemCol.SetImage(-1);

  itemCol.SetAlign(wxLIST_FORMAT_CENTRE);

  lc->InsertColumn(3, itemCol);

  lc->SetColumnWidth(0, wxLIST_AUTOSIZE);

  lc->SetColumnWidth(1, wxLIST_AUTOSIZE);

  lc->SetColumnWidth(2, wxLIST_AUTOSIZE);

  lc->SetColumnWidth(3, wxLIST_AUTOSIZE);

  lc->Show();

  sizer->Add(lc, 1, wxEXPAND | wxALL, 0);

  panel->SetSizer(sizer);

  book->AddPage(panel, "Download/Upload");

}
void
MainWnd::OnSearchResultActivated(wxListEvent& event)
{

  wxString str;
  FILE_INFO* fi = NULL;

  do {

    fi = (FILE_INFO*)event.GetData();

    if (!m_kn_running) break;

    kadnet_search_file(
                       m_kn,
                       fi->file_id,
                       fi->file_name,
                       fi->file_size
                      );

  } while (false);

}
