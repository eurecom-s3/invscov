//
// Generated by JTB 1.3.2
//

package jtb.syntaxtree;

// Grammar production:
// f0 -> <IDENTIFIER>
// f1 -> [ TypeArguments() ]
// f2 -> ( "." <IDENTIFIER> [ TypeArguments() ] )*
public class ClassOrInterfaceType implements Node {
   // This was added after running jtb to remove serializable warning.
   static final long serialVersionUID = 20150406L;

   // Added member variable to suport
   // tools/jtb/ClassOrInterfaceTypeDecorateVisitor.java.  (markro)
   public ClassOrInterfaceType unGenerifiedVersionOfThis = null;

   private Node parent;
   public NodeToken f0;
   public NodeOptional f1;
   public NodeListOptional f2;

   public ClassOrInterfaceType(NodeToken n0, NodeOptional n1, NodeListOptional n2) {
      f0 = n0;
      if ( f0 != null ) f0.setParent(this);
      f1 = n1;
      if ( f1 != null ) f1.setParent(this);
      f2 = n2;
      if ( f2 != null ) f2.setParent(this);
   }

   public void accept(jtb.visitor.Visitor v) {
      v.visit(this);
   }
   public <R,A> R accept(jtb.visitor.GJVisitor<R,A> v, A argu) {
      return v.visit(this,argu);
   }
   public <R> R accept(jtb.visitor.GJNoArguVisitor<R> v) {
      return v.visit(this);
   }
   public <A> void accept(jtb.visitor.GJVoidVisitor<A> v, A argu) {
      v.visit(this,argu);
   }
   public void setParent(Node n) { parent = n; }
   public Node getParent()       { return parent; }
}
