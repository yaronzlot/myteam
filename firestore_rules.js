rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {

    // ---------- עזרים ----------
    function signedIn() {
      return request.auth != null && request.auth.token.email != null;
    }
    function me() {
      return request.auth.token.email.lower();
    }
    // סופר אדמין: גישה מלאה לכל המועדונים. להוספת עוד אחד, הוסף אימייל לרשימה (ובקוד index.html)
    function isSuperEmail(e) {
      return e in ['yaron.zlotolov@gmail.com'];
    }
    function isSuperAdmin() {
      return signedIn() && request.auth.token.email_verified == true && isSuperEmail(me());
    }
    // הקמת מועדונים ראשיים וענפים (תתי-מועדונים): רק סופר אדמין
    function canCreateClub() {
      return isSuperAdmin();
    }
    function clubPath(clubId) {
      return /databases/$(database)/documents/clubs/$(clubId);
    }
    function memberPath(clubId) {
      return /databases/$(database)/documents/memberships/$(clubId + '__' + me());
    }
    function isOwner(clubId) {
      return isSuperAdmin()
             || (signedIn() && exists(clubPath(clubId))
                 && get(clubPath(clubId)).data.ownerEmail == me());
    }
    function isAdmin(clubId) {
      return isOwner(clubId)
             || (signedIn() && exists(memberPath(clubId))
                 && get(memberPath(clubId)).data.role == 'admin');
    }
    function isCoach(clubId) {
      return signedIn() && exists(memberPath(clubId))
             && get(memberPath(clubId)).data.role == 'coach';
    }
    function isMember(clubId) {
      return isAdmin(clubId) || isCoach(clubId);
    }
    function coachTeams(clubId) {
      return get(memberPath(clubId)).data.teams;
    }

    // ---------- מועדונים / ענפים ----------
    match /clubs/{clubId} {
      allow read: if true;
      allow create: if canCreateClub() && request.resource.data.ownerEmail == me();
      // מנהל רגיל יכול לעדכן הגדרות (צבע, לוגו) אך לא את המנהל הראשי
      // שיוך למועדון ראשי (orgId) - רק סופר אדמין
      allow update: if isSuperAdmin()
                    || ((isOwner(clubId)
                         || (isAdmin(clubId)
                             && request.resource.data.ownerEmail == resource.data.ownerEmail))
                        && request.resource.data.get('orgId', '') == resource.data.get('orgId', ''));
      allow delete: if false;

      match /teams/{id} {
        allow read: if true;
        allow write: if isAdmin(clubId);
      }
      match /venues/{id} {
        allow read: if true;
        allow write: if isAdmin(clubId);
      }
      match /players/{id} {
        allow read: if true;   // נדרש כי שחקנים נכנסים בטלפון בלי אימות (ראה הערה)
        allow create: if isAdmin(clubId)
                      || (isCoach(clubId) && request.resource.data.team in coachTeams(clubId));
        allow update: if isAdmin(clubId)
                      || (isCoach(clubId)
                          && resource.data.team in coachTeams(clubId)
                          && request.resource.data.team in coachTeams(clubId));
        allow delete: if isAdmin(clubId)
                      || (isCoach(clubId) && resource.data.team in coachTeams(clubId));
      }
      match /schedules/{id} {
        allow read: if true;
        allow create: if isAdmin(clubId)
                      || (isCoach(clubId) && request.resource.data.team in coachTeams(clubId));
        allow update: if isAdmin(clubId)
                      || (isCoach(clubId)
                          && resource.data.team in coachTeams(clubId)
                          && request.resource.data.team in coachTeams(clubId));
        allow delete: if isAdmin(clubId)
                      || (isCoach(clubId) && resource.data.team in coachTeams(clubId));
      }
      // משחקים וכיבוד (הורים שמביאים כיבוד): קריאה לכולם (שחקנים/הורים נכנסים בטלפון), כתיבה למנהל ולמאמן של הקבוצה
      match /games/{id} {
        allow read: if true;
        allow create: if isAdmin(clubId)
                      || (isCoach(clubId) && request.resource.data.team in coachTeams(clubId));
        allow update: if isAdmin(clubId)
                      || (isCoach(clubId)
                          && resource.data.team in coachTeams(clubId)
                          && request.resource.data.team in coachTeams(clubId));
        allow delete: if isAdmin(clubId)
                      || (isCoach(clubId) && resource.data.team in coachTeams(clubId));
      }
      // הכנסות והוצאות (הגדרות כספים): מנהלים בלבד
      match /finance/{id} {
        allow read, write: if isAdmin(clubId);
      }
      // תבנית אימונים שבועית לכל קבוצה (מזהה המסמך = שם הקבוצה)
      match /weeklyTemplates/{id} {
        allow read: if isMember(clubId);
        allow create: if isAdmin(clubId)
                      || (isCoach(clubId) && request.resource.data.team in coachTeams(clubId));
        allow update: if isAdmin(clubId)
                      || (isCoach(clubId)
                          && resource.data.team in coachTeams(clubId)
                          && request.resource.data.team in coachTeams(clubId));
        allow delete: if isAdmin(clubId)
                      || (isCoach(clubId) && resource.data.team in coachTeams(clubId));
      }
    }

    // ---------- הרשאות: מנהלים ומאמנים (מזהה: clubId__email) ----------
    match /memberships/{mid} {
      allow read: if signedIn()
                  && (resource.data.email == me() || isAdmin(resource.data.clubId));
      allow create, update: if isAdmin(request.resource.data.clubId)
                  && mid == request.resource.data.clubId + '__' + request.resource.data.email
                  && request.resource.data.role in ['admin', 'coach'];
      // אי אפשר למחוק את המנהל הראשי
      allow delete: if isAdmin(resource.data.clubId)
                  && !isSuperEmail(resource.data.email)
                  && resource.data.email != get(clubPath(resource.data.clubId)).data.ownerEmail;
    }

    // ---------- מי רשאי להקים מועדונים חדשים (מעבר לסופר אדמין) ----------
    match /clubCreators/{email} {
      allow read: if signedIn() && email == me();
      allow write: if isSuperAdmin();
    }

    // ---------- מועדונים ראשיים (כל מועדון ראשי מכיל ענפים: כדורסל / כדורגל / כדורעף) ----------
    match /orgs/{orgId} {
      allow read: if true;
      allow create, update: if isSuperAdmin();
      allow delete: if false;
    }

    // ---------- אינדקס טלפון -> מועדונים (לכניסת שחקנים) ----------
    match /phoneIndex/{phone}/clubs/{clubId} {
      allow read: if true;
      allow write: if isMember(clubId);
    }

    // ---------- נתוני המבנה הישן (קריאה בלבד, להעברה חד-פעמית) ----------
    match /settings/{d}  { allow read: if signedIn(); allow write: if false; }
    match /teams/{d}     { allow read: if signedIn(); allow write: if false; }
    match /venues/{d}    { allow read: if signedIn(); allow write: if false; }
    match /players/{d}   { allow read: if signedIn(); allow write: if false; }
    match /schedules/{d} { allow read: if signedIn(); allow write: if false; }
    match /admins/{d}    { allow read: if signedIn(); allow write: if false; }
    match /coaches/{d}   { allow read: if signedIn(); allow write: if false; }
  }
}
