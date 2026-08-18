
const express=require("express");
const path=require("path");
const fs=require("fs");
const helmet=require("helmet");
const bcrypt=require("bcryptjs");
const jwt=require("jsonwebtoken");
const db=require("./db");

const app=express();
const PORT=process.env.PORT||3000;
const ROOT=path.join(__dirname,"..");
const JWT_SECRET=process.env.JWT_SECRET||"CHANGE_THIS_IN_PRODUCTION";
app.use(helmet({contentSecurityPolicy:false}));
app.use(express.json({limit:"1mb"}));

function nationalIdValid(code){
  if(!/^\d{10}$/.test(code) || /^(\d)\1{9}$/.test(code)) return false;
  let sum=0; for(let i=0;i<9;i++) sum += Number(code[i])*(10-i);
  const r=sum%11;
  return r<2 ? Number(code[9])===r : Number(code[9])===11-r;
}
function seed(){
  const count=db.prepare("SELECT COUNT(*) c FROM students").get().c;
  if(count>0)return;
  const hash=bcrypt.hashSync("123456",12);
  const student=db.prepare("INSERT INTO students(national_id,password_hash,first_name,last_name,grade,field,class_name) VALUES(?,?,?,?,?,?,?)")
    .run("1000000001",hash,"محمدرضا","احمدی","دهم","علوم انسانی","۱۰۲");
  const classes=[
    ["ریاضی","استاد علوی","شنبه","۸:۰۰"],
    ["فارسی","استاد محمدی","شنبه","۱۰:۰۰"],
    ["عربی","استاد کریمی","یکشنبه","۸:۰۰"],
    ["اقتصاد","استاد احمدی","یکشنبه","۱۰:۰۰"]
  ];
  const insertClass=db.prepare("INSERT INTO classes(title,teacher,weekday,time) VALUES(?,?,?,?)");
  const ids=classes.map(c=>insertClass.run(...c).lastInsertRowid);
  const insEnroll=db.prepare("INSERT INTO enrollments(student_id,class_id) VALUES(?,?)");
  ids.forEach(id=>insEnroll.run(student.lastInsertRowid,id));
  const insGrade=db.prepare("INSERT INTO grades(student_id,subject,score,term) VALUES(?,?,?,?)");
  [["ریاضی",19.5,"نوبت اول"],["فارسی",19,"نوبت اول"],["عربی",19.25,"نوبت اول"],["اقتصاد",19.3,"نوبت اول"]].forEach(x=>insGrade.run(student.lastInsertRowid,...x));
  const insConsent=db.prepare("INSERT INTO consents(student_id,title,status,updated_at) VALUES(?,?,?,?)");
  insConsent.run(student.lastInsertRowid,"رضایت‌نامه اردوی علمی","pending","");
  insConsent.run(student.lastInsertRowid,"رضایت‌نامه برنامه فرهنگی","done",new Date().toISOString());
  insConsent.run(student.lastInsertRowid,"رضایت‌نامه استفاده از اینترنت","pending","");
  const now=new Date().toISOString();
  db.prepare("INSERT INTO announcements(title,body,audience,created_at) VALUES(?,?,?,?)").run("اطلاعیه جلسه اولیا و مربیان","جزئیات برنامه در مدرسه اعلام شده است.","all",now);
  db.prepare("INSERT INTO announcements(title,body,audience,created_at) VALUES(?,?,?,?)").run("برنامه اردوی علمی","اطلاعیه ویژه دانش‌آموزان پایه دهم.","grade:d10",now);
  const insExam=db.prepare("INSERT INTO exams(student_id,subject,exam_date) VALUES(?,?,?)");
  insExam.run(student.lastInsertRowid,"ریاضی","1405/06/12");
  insExam.run(student.lastInsertRowid,"عربی","1405/06/15");
}
seed();

function auth(req,res,next){
  const token=req.headers.authorization?.replace(/^Bearer\s+/,"") || req.cookies?.token;
  if(!token)return res.status(401).json({error:"unauthorized"});
  try{req.user=jwt.verify(token,JWT_SECRET);next()}catch(e){return res.status(401).json({error:"unauthorized"})}
}
app.post("/api/auth/login",(req,res)=>{
  const {nationalId,password}=req.body||{};
  if(!nationalIdValid(String(nationalId||"")))return res.status(400).json({error:"کد ملی معتبر نیست"});
  const st=db.prepare("SELECT * FROM students WHERE national_id=?").get(String(nationalId));
  if(!st || !bcrypt.compareSync(String(password||""),st.password_hash))return res.status(401).json({error:"کد ملی یا رمز عبور نادرست است"});
  const token=jwt.sign({id:st.id,role:"student"},JWT_SECRET,{expiresIn:"8h"});
  res.json({token});
});
app.get("/api/student/dashboard",auth,(req,res)=>{
  if(req.user.role!=="student")return res.status(403).json({error:"forbidden"});
  const st=db.prepare("SELECT id,national_id,first_name,last_name,grade,field,class_name,photo FROM students WHERE id=?").get(req.user.id);
  if(!st)return res.status(404).json({error:"student_not_found"});
  const classes=db.prepare(`SELECT c.title,c.teacher,c.weekday,c.time FROM classes c JOIN enrollments e ON e.class_id=c.id WHERE e.student_id=? ORDER BY c.id`).all(st.id);
  const grades=db.prepare("SELECT subject,score,term FROM grades WHERE student_id=? ORDER BY id DESC").all(st.id);
  const consents=db.prepare("SELECT title,status,updated_at FROM consents WHERE student_id=? ORDER BY id DESC").all(st.id);
  const exams=db.prepare("SELECT subject,exam_date FROM exams WHERE student_id=? ORDER BY exam_date").all(st.id);
  const announcements=db.prepare("SELECT title,body,created_at FROM announcements WHERE audience='all' OR audience=? ORDER BY id DESC LIMIT 10").all("grade:d10");
  const avg=grades.length?grades.reduce((a,g)=>a+g.score,0)/grades.length:0;
  res.json({student:st,classes,grades,average:Number(avg.toFixed(2)),consents,exams,announcements});
});
app.post("/api/auth/logout",(req,res)=>res.json({ok:true}));
app.use(express.static(ROOT));
app.use((req,res,next)=>{ if(req.method==="GET" && !req.path.startsWith("/api/")) return res.sendFile(path.join(ROOT,"index.html")); next(); });
app.listen(PORT,()=>console.log(`Shooshtar Sampad running on http://localhost:${PORT}`));
